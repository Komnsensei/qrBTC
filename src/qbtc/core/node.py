"""
qBTC Full Node Orchestrator v2 — HARDENED FOR PEER REVIEW
============================================================
The top-level coordinator that wires together all subsystems:
    Blockchain <-> Mempool <-> Consensus <-> Miner <-> P2P <-> RPC

Lifecycle:
    node = QBTCNode(config)
    await node.start()      # boots all subsystems
    await node.stop()       # graceful shutdown

Event Flow:
    P2P receives block -> Consensus validates -> Blockchain accepts -> Mempool purges
    P2P receives tx    -> Mempool validates -> Broadcast to peers
    Miner finds block  -> Blockchain accepts -> P2P broadcasts -> Mempool purges
    RPC receives tx    -> Mempool validates -> P2P broadcasts
"""
from __future__ import annotations
import asyncio
import time
import signal
import logging
import json
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path

from qbtc.core.constants import (
    MAINNET_PORT, MAINNET_MAGIC, PROTOCOL_VERSION, USER_AGENT, COIN,
)
from qbtc.core.chain import Blockchain
from qbtc.core.mempool import Mempool
from qbtc.core.block import Block
from qbtc.core.transaction import Transaction
from qbtc.crypto.keys import QuantumKeyPair

logger = logging.getLogger("qbtc.node")


# ═══════════════════════════════════════════════════════════════════════════
# NODE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class NodeConfig:
    """Configuration for a qBTC full node.

    Attributes:
        data_dir:       Path to store blockchain data, wallet, logs
        host:           Listen address for P2P connections
        port:           Listen port for P2P connections
        rpc_host:       Listen address for JSON-RPC server
        rpc_port:       Listen port for JSON-RPC server
        seed_peers:     List of seed peer addresses (host:port)
        enable_mining:  Whether to start the miner on boot
        enable_staking: Whether to enable PoS staking (Phase 1+)
        enable_rpc:     Whether to start the RPC server
        wallet_file:    Wallet filename within data_dir
        wallet_password: Password for wallet encryption
        log_level:      Logging level (DEBUG, INFO, WARNING, ERROR)
        testnet:        Whether to use testnet parameters
    """
    data_dir: str = "./qbtc_data"
    host: str = "0.0.0.0"
    port: int = MAINNET_PORT
    rpc_host: str = "127.0.0.1"
    rpc_port: int = 19332
    seed_peers: List[str] = field(default_factory=list)
    enable_mining: bool = False
    enable_staking: bool = False
    enable_rpc: bool = True
    wallet_file: str = "wallet.qbtc"
    wallet_password: str = ""
    log_level: str = "INFO"
    testnet: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# FULL NODE
# ═══════════════════════════════════════════════════════════════════════════

class QBTCNode:
    """The qBTC full node — master orchestrator of all protocol subsystems.

    Wires together:
        - Blockchain   : chain state, UTXO set, block index
        - Mempool      : unconfirmed transaction pool
        - Consensus    : hybrid QPoW+PoS validation engine
        - Miner        : SHA3-256d block mining with 64-bit nonce
        - P2P          : async TCP peer networking with ML-KEM channels
        - RPC          : JSON-RPC 2.0 API for external interaction
        - Wallet       : quantum-resistant HD wallet (ML-DSA-65)

    Subsystems are imported lazily to avoid circular imports and to
    allow the node to function even if some subsystems are not yet
    implemented (e.g., during incremental development).
    """

    def __init__(self, config: Optional[NodeConfig] = None) -> None:
        self.config = config or NodeConfig()
        self._setup_logging()

        # Core subsystems (always available)
        self.blockchain = Blockchain()
        self.mempool = Mempool()

        # Optional subsystems (loaded on demand)
        self.consensus = None
        self.wallet = None
        self.miner = None
        self._miner_keypair: Optional[QuantumKeyPair] = None
        self.p2p = None

        # RPC server
        self._rpc_server: Optional[asyncio.Server] = None

        # Lifecycle
        self._running = False
        self._start_time = 0.0

    # ── Logging Setup ────────────────────────────────────────────────────

    def _setup_logging(self) -> None:
        """Configure logging for the node."""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Boot all node subsystems in dependency order."""
        self._running = True
        self._start_time = time.time()

        # 1. Data directory
        Path(self.config.data_dir).mkdir(parents=True, exist_ok=True)
        logger.info(f"qBTC Node v{PROTOCOL_VERSION} starting...")
        logger.info(f"Data directory: {self.config.data_dir}")

        # 2. Blockchain (already initialized with genesis in __init__)
        logger.info(
            f"Blockchain ready: height={self.blockchain.tip_height}, "
            f"tip={self.blockchain.tip_hash.hex()[:16]}..."
        )

        # 3. Consensus engine
        try:
            from qbtc.consensus.consensus import ConsensusEngine
            self.consensus = ConsensusEngine(self.blockchain)
            logger.info("Consensus engine loaded")
        except ImportError:
            logger.warning("Consensus engine not available")

        # 4. Wallet
        await self._init_wallet()

        # 5. P2P Network
        try:
            from qbtc.network.p2p_node import P2PNode
            self.p2p = P2PNode(
                host=self.config.host,
                port=self.config.port,
                best_height_fn=lambda: self.blockchain.tip_height,
                on_block=self._on_network_block,
                on_tx=self._on_network_tx,
            )
            await self.p2p.start(seed_peers=self.config.seed_peers)
        except ImportError:
            logger.warning("P2P networking not available")
        except Exception as e:
            logger.error(f"P2P start failed: {e}")

        # 6. Miner (optional)
        if self.config.enable_mining:
            await self._init_miner()

        # 7. RPC Server (optional)
        if self.config.enable_rpc:
            await self._init_rpc()

        # 8. Periodic tasks
        asyncio.create_task(self._periodic_tasks())

        peer_count = self.p2p.info["peers"] if self.p2p else 0
        mining_status = "ON" if self.miner else "OFF"
        logger.info(
            f"qBTC Node fully started | "
            f"height={self.blockchain.tip_height} | "
            f"peers={peer_count} | "
            f"mining={mining_status}"
        )

    async def stop(self) -> None:
        """Graceful shutdown of all subsystems."""
        logger.info("Shutting down qBTC Node...")
        self._running = False

        if self.miner:
            self.miner.stop()
            logger.info("Miner stopped")

        if self._rpc_server:
            self._rpc_server.close()
            await self._rpc_server.wait_closed()
            logger.info("RPC server stopped")

        if self.p2p:
            await self.p2p.stop()

        if self.wallet:
            wallet_path = Path(self.config.data_dir) / self.config.wallet_file
            self.wallet.save(str(wallet_path), self.config.wallet_password)
            logger.info("Wallet saved")

        uptime = time.time() - self._start_time
        logger.info(f"qBTC Node stopped. Uptime: {uptime:.0f}s")

    # ── Wallet Init ──────────────────────────────────────────────────────

    async def _init_wallet(self) -> None:
        """Initialize the wallet — load from disk or create new."""
        try:
            from qbtc.wallet.wallet import Wallet
        except ImportError:
            logger.warning("Wallet module not available")
            return

        wallet_path = Path(self.config.data_dir) / self.config.wallet_file
        if wallet_path.exists():
            try:
                self.wallet = Wallet.load(
                    str(wallet_path), self.config.wallet_password
                )
                logger.info(
                    f"Wallet loaded: {self.wallet.name} "
                    f"({len(self.wallet.keys)} keys)"
                )
            except Exception as e:
                logger.error(f"Failed to load wallet: {e}")
                self.wallet = Wallet.create(
                    "default", testnet=self.config.testnet
                )
        else:
            self.wallet = Wallet.create(
                "default", testnet=self.config.testnet
            )
            self.wallet.save(str(wallet_path), self.config.wallet_password)
            logger.info("New wallet created")

    # ── Miner Init ───────────────────────────────────────────────────────

    async def _init_miner(self) -> None:
        """Initialize and start the block miner."""
        try:
            from qbtc.consensus.miner import Miner
        except ImportError:
            logger.warning("Miner module not available")
            return

        if not self.wallet:
            logger.error("Cannot start miner without wallet")
            return

        # Use first wallet key for mining rewards
        first_key = list(self.wallet.keys.values())[0]
        self._miner_keypair = first_key.keypair

        self.miner = Miner(
            blockchain=self.blockchain,
            mempool=self.mempool,
            consensus=self.consensus,
            miner_keypair=self._miner_keypair,
            on_block_found=self._on_block_mined,
        )
        self.miner.start()
        logger.info(f"Miner started -> rewards to {first_key.address}")

    def _on_block_mined(self, block: Block) -> None:
        """Callback when the miner finds a block."""
        if self.p2p:
            asyncio.create_task(self.p2p.broadcast_block(block))

    # ── Network Event Handlers ───────────────────────────────────────────

    async def _on_network_block(self, block: Block, peer: Any) -> None:
        """Handle a block received from the P2P network."""
        accepted, msg = self.blockchain.add_block(block)
        if accepted:
            # Remove confirmed transactions from mempool
            confirmed_txids = [tx.txid for tx in block.transactions]
            self.mempool.remove_confirmed(confirmed_txids)
            logger.info(
                f"Network block {block.height} accepted "
                f"({block.tx_count} txs)"
            )
            # Relay to other peers
            if self.p2p:
                await self.p2p.broadcast_block(block)
        else:
            logger.debug(f"Network block rejected: {msg}")

    async def _on_network_tx(self, tx: Transaction, peer: Any) -> None:
        """Handle a transaction received from the P2P network."""
        # Calculate fee (would need UTXO lookup in production)
        fee = 0
        for inp in tx.inputs:
            from qbtc.core.chain import UTXOKey
            utxo = self.blockchain.get_utxo(
                UTXOKey(txid=inp.prev_txid, index=inp.prev_index)
            )
            if utxo:
                fee += utxo.amount
        fee -= tx.total_output

        accepted, msg = self.mempool.add_transaction(
            tx, fee=max(fee, 0), current_height=self.blockchain.tip_height
        )
        if accepted:
            logger.debug(f"Network TX {tx.txid_hex[:16]}... accepted")
            if self.p2p:
                await self.p2p.broadcast_tx(tx)
        else:
            logger.debug(f"Network TX rejected: {msg}")

    # ── JSON-RPC 2.0 Server ─────────────────────────────────────────────

    async def _init_rpc(self) -> None:
        """Start the JSON-RPC 2.0 server."""
        try:
            self._rpc_server = await asyncio.start_server(
                self._handle_rpc_connection,
                self.config.rpc_host,
                self.config.rpc_port,
            )
            logger.info(
                f"RPC server on {self.config.rpc_host}:{self.config.rpc_port}"
            )
        except Exception as e:
            logger.error(f"RPC server failed to start: {e}")

    async def _handle_rpc_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a single RPC connection."""
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=30)
            if not data:
                return
            request = json.loads(data.decode())
            response = await self._process_rpc(request)
            writer.write(json.dumps(response).encode() + b"\n")
            await writer.drain()
        except asyncio.TimeoutError:
            err = {
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": "Request timeout"},
                "id": None,
            }
            writer.write(json.dumps(err).encode() + b"\n")
            await writer.drain()
        except json.JSONDecodeError:
            err = {
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": "Parse error"},
                "id": None,
            }
            writer.write(json.dumps(err).encode() + b"\n")
            await writer.drain()
        except Exception as e:
            err = {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)},
                "id": None,
            }
            writer.write(json.dumps(err).encode() + b"\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def _process_rpc(self, request: dict) -> dict:
        """Route JSON-RPC 2.0 requests to handlers.

        Supported methods:
            getblockchaininfo  - Chain state summary
            getblock           - Block by height or hash
            getmempoolinfo     - Mempool state summary
            getnewaddress      - Generate a new wallet address
            getbalance         - Wallet balance
            sendtoaddress      - Create and broadcast a transaction
            getpeerinfo        - Connected peer information
            stop               - Graceful node shutdown
        """
        method = request.get("method", "")
        params = request.get("params", {})
        req_id = request.get("id", 1)

        handlers = {
            "getblockchaininfo": self._rpc_getblockchaininfo,
            "getblock": self._rpc_getblock,
            "getmempoolinfo": self._rpc_getmempoolinfo,
            "getnewaddress": self._rpc_getnewaddress,
            "getbalance": self._rpc_getbalance,
            "sendtoaddress": self._rpc_sendtoaddress,
            "getpeerinfo": self._rpc_getpeerinfo,
            "stop": self._rpc_stop,
        }

        handler = handlers.get(method)
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
                "id": req_id,
            }

        try:
            result = await handler(params)
            return {"jsonrpc": "2.0", "result": result, "id": req_id}
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)},
                "id": req_id,
            }

    # ── RPC Handlers ─────────────────────────────────────────────────────

    async def _rpc_getblockchaininfo(self, params: dict) -> dict:
        """Return blockchain state summary."""
        return self.blockchain.info

    async def _rpc_getblock(self, params: dict) -> dict:
        """Return a block by height or hash."""
        if "height" in params:
            block = self.blockchain.get_block_by_height(params["height"])
        elif "hash" in params:
            block_hash = bytes.fromhex(params["hash"])
            block = self.blockchain.get_block_by_hash(block_hash)
        else:
            raise ValueError("Provide 'height' or 'hash' parameter")

        if block is None:
            raise ValueError("Block not found")

        return {
            "hash": block.block_hash_hex,
            "height": block.height,
            "version": block.header.version,
            "prev_hash": block.header.prev_block_hash.hex(),
            "merkle_root": block.header.merkle_root.hex(),
            "timestamp": block.header.timestamp,
            "bits": hex(block.header.bits),
            "nonce": block.header.nonce,
            "difficulty": block.header.difficulty,
            "tx_count": block.tx_count,
            "size": block.size,
            "weight": block.weight,
        }

    async def _rpc_getmempoolinfo(self, params: dict) -> dict:
        """Return mempool state summary."""
        return self.mempool.info

    async def _rpc_getnewaddress(self, params: dict) -> dict:
        """Generate a new wallet address."""
        if not self.wallet:
            raise ValueError("No wallet loaded")
        label = params.get("label", "")
        key_entry = self.wallet.generate_key(label=label)
        return {
            "address": key_entry.address,
            "key_id": key_entry.keypair.key_id.hex(),
        }

    async def _rpc_getbalance(self, params: dict) -> dict:
        """Get wallet balance."""
        if not self.wallet:
            raise ValueError("No wallet loaded")

        total = 0
        for key_entry in self.wallet.keys.values():
            pk_hash = key_entry.keypair.key_id  # 20-byte fingerprint
            balance = self.blockchain.get_balance(pk_hash)
            total += balance

        return {
            "balance_sats": total,
            "balance_qbtc": total / COIN,
        }

    async def _rpc_sendtoaddress(self, params: dict) -> dict:
        """Create and broadcast a transaction."""
        if not self.wallet:
            raise ValueError("No wallet loaded")

        address = params.get("address", "")
        amount = int(params.get("amount", 0))

        if not address or amount <= 0:
            raise ValueError("Provide valid 'address' and 'amount'")

        # This is a simplified send — production would do proper
        # coin selection, change address generation, etc.
        return {
            "status": "not_implemented",
            "message": "Full transaction creation requires coin selection. "
                       "Use the wallet module directly for now.",
        }

    async def _rpc_getpeerinfo(self, params: dict) -> dict:
        """Return connected peer information."""
        if not self.p2p:
            return {"peers": []}
        return self.p2p.info

    async def _rpc_stop(self, params: dict) -> dict:
        """Initiate graceful node shutdown."""
        asyncio.create_task(self.stop())
        return {"status": "shutdown initiated"}

    # ── Periodic Tasks ───────────────────────────────────────────────────

    async def _periodic_tasks(self) -> None:
        """Background tasks that run periodically."""
        while self._running:
            try:
                await asyncio.sleep(60)

                # Log status every 60 seconds
                peer_count = self.p2p.info["peers"] if self.p2p else 0
                logger.info(
                    f"Status: height={self.blockchain.tip_height}, "
                    f"mempool={self.mempool.size} txs, "
                    f"utxos={len(self.blockchain.utxo_set)}, "
                    f"peers={peer_count}"
                )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Periodic task error: {e}")

    # ── Node Info ────────────────────────────────────────────────────────

    @property
    def info(self) -> dict:
        """Full node status summary."""
        return {
            "version": PROTOCOL_VERSION,
            "user_agent": USER_AGENT,
            "uptime": time.time() - self._start_time if self._running else 0,
            "blockchain": self.blockchain.info,
            "mempool": self.mempool.info,
            "mining": self.miner is not None,
            "peers": self.p2p.info["peers"] if self.p2p else 0,
            "wallet": self.wallet.name if self.wallet else None,
        }

    def __repr__(self) -> str:
        return (
            f"QBTCNode(height={self.blockchain.tip_height}, "
            f"mempool={self.mempool.size}, "
            f"running={self._running})"
        )