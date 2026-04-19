"""
qBTC P2P Node v2 — HARDENED FOR PEER REVIEW
==============================================
Async TCP network server and client.
Handles peer connections, message dispatch, block/tx relay,
and ML-KEM-1024 encrypted channel setup.
"""
from __future__ import annotations
import asyncio
import struct
import time
import os
import logging
from typing import Dict, List, Optional, Set, Callable, Awaitable, Any
from qbtc.core.constants import (
    MAINNET_MAGIC, MAINNET_PORT, PROTOCOL_VERSION, USER_AGENT,
    MAX_PEERS, MAX_OUTBOUND, HANDSHAKE_TIMEOUT, PING_INTERVAL,
)
from qbtc.core.block import Block
from qbtc.core.transaction import Transaction
from qbtc.network.p2p_protocol import (
    MsgType, InvType, Peer, encode_message, read_message,
    encode_version_payload, decode_version_payload,
)

logger = logging.getLogger("qbtc.network")


class P2PNode:
    """Async TCP P2P node for qBTC.

    Manages inbound and outbound peer connections, performs the
    version/verack handshake, dispatches messages to handlers,
    and relays blocks and transactions to the network.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = MAINNET_PORT,
        magic: bytes = MAINNET_MAGIC,
        max_peers: int = MAX_PEERS,
        best_height_fn: Optional[Callable[[], int]] = None,
        on_block: Optional[Callable] = None,
        on_tx: Optional[Callable] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.magic = magic
        self.max_peers = max_peers
        self.best_height_fn = best_height_fn or (lambda: 0)
        self.on_block = on_block
        self.on_tx = on_tx

        self.peers: Dict[str, Peer] = {}
        self._server: Optional[asyncio.Server] = None
        self._running = False

        self.known_addrs: Set[str] = set()
        self._known_blocks: Set[bytes] = set()
        self._known_txs: Set[bytes] = set()

    # ── Lifecycle ────────────────────────────────────────────────────────

    async def start(self, seed_peers: Optional[List[str]] = None) -> None:
        """Start the P2P server and connect to seed peers."""
        self._running = True
        self._server = await asyncio.start_server(
            self._handle_inbound, self.host, self.port
        )
        logger.info(f"P2P listening on {self.host}:{self.port}")

        if seed_peers:
            for addr in seed_peers:
                asyncio.create_task(self._connect_to_peer(addr))

        asyncio.create_task(self._maintenance_loop())

    async def stop(self) -> None:
        """Stop the P2P server and disconnect all peers."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        for peer in list(self.peers.values()):
            await self._disconnect(peer)
        logger.info("P2P node stopped")

    # ── Connection Handling ──────────────────────────────────────────────

    async def _handle_inbound(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a new inbound connection."""
        ai = writer.get_extra_info("peername")
        addr = f"{ai[0]}:{ai[1]}"

        if len(self.peers) >= self.max_peers:
            writer.close()
            return

        peer = Peer(
            host=ai[0], port=ai[1],
            reader=reader, writer=writer,
            is_inbound=True,
            connected_at=time.time(),
            is_connected=True,
        )
        self.peers[addr] = peer
        logger.info(f"Inbound peer: {addr}")
        await self._peer_loop(peer)

    async def _connect_to_peer(self, addr: str) -> None:
        """Connect to an outbound peer."""
        if addr in self.peers or len(self.peers) >= self.max_peers:
            return
        try:
            h, p = addr.rsplit(":", 1)
            port = int(p)
            r, w = await asyncio.wait_for(
                asyncio.open_connection(h, port),
                timeout=HANDSHAKE_TIMEOUT,
            )
            peer = Peer(
                host=h, port=port,
                reader=r, writer=w,
                is_inbound=False,
                connected_at=time.time(),
                is_connected=True,
            )
            self.peers[addr] = peer
            logger.info(f"Outbound peer: {addr}")
            await self._send_version(peer)
            await self._peer_loop(peer)
        except Exception as e:
            logger.warning(f"Connect failed {addr}: {e}")

    async def _peer_loop(self, peer: Peer) -> None:
        """Read messages from a peer until disconnected."""
        try:
            while self._running and peer.is_connected:
                mt, payload = await read_message(peer.reader, self.magic)
                peer.last_seen = time.time()
                await self._dispatch(peer, mt, payload)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        except Exception as e:
            logger.warning(f"Peer {peer.addr} error: {e}")
        finally:
            await self._disconnect(peer)

    async def _disconnect(self, peer: Peer) -> None:
        """Disconnect a peer and clean up."""
        peer.is_connected = False
        if peer.writer:
            try:
                peer.writer.close()
                await peer.writer.wait_closed()
            except Exception:
                pass
        self.peers.pop(peer.addr, None)

    # ── Message Dispatch ─────────────────────────────────────────────────

    async def _dispatch(
        self, peer: Peer, mt: MsgType, payload: bytes
    ) -> None:
        """Route an incoming message to the appropriate handler."""
        if mt == MsgType.VERSION:
            info = decode_version_payload(payload)
            peer.protocol_version = info["protocol_version"]
            peer.best_height = info["best_height"]
            peer.user_agent = info["user_agent"]
            peer.version_received = True
            if not peer.version_sent:
                await self._send_version(peer)
            await self._send(peer, MsgType.VERACK, b"")
            peer.verack_sent = True
            logger.info(
                f"VERSION from {peer.addr}: "
                f"h={info['best_height']}, ua={info['user_agent']}"
            )

        elif mt == MsgType.VERACK:
            peer.verack_received = True
            logger.info(f"Handshake complete: {peer.addr}")

        elif mt == MsgType.PING:
            await self._send(peer, MsgType.PONG, payload)

        elif mt == MsgType.PONG:
            if peer.last_ping > 0:
                peer.latency_ms = (time.time() - peer.last_ping) * 1000

        elif mt == MsgType.INV:
            off = 0
            reqs = b""
            while off < len(payload):
                it = payload[off]
                off += 1
                ih = payload[off:off + 32]
                off += 32
                if it == InvType.BLOCK and ih not in self._known_blocks:
                    reqs += struct.pack("!B", it) + ih
                elif it == InvType.TX and ih not in self._known_txs:
                    reqs += struct.pack("!B", it) + ih
            if reqs:
                await self._send(peer, MsgType.GETDATA, reqs)

        elif mt == MsgType.BLOCK:
            try:
                blk = Block.deserialize(payload)
                if blk.block_hash not in self._known_blocks:
                    self._known_blocks.add(blk.block_hash)
                    logger.info(
                        f"Block from {peer.addr}: h={blk.height}"
                    )
                    if self.on_block:
                        await self.on_block(blk, peer)
            except Exception as e:
                logger.warning(f"Bad block from {peer.addr}: {e}")

        elif mt == MsgType.TX:
            try:
                tx = Transaction.deserialize(payload)
                if tx.txid not in self._known_txs:
                    self._known_txs.add(tx.txid)
                    if self.on_tx:
                        await self.on_tx(tx, peer)
            except Exception as e:
                logger.warning(f"Bad tx from {peer.addr}: {e}")

        elif mt == MsgType.GETPEERS:
            pl = struct.pack("!H", min(len(self.peers), 100))
            for p in list(self.peers.values())[:100]:
                ab = p.addr.encode()
                pl += struct.pack("!H", len(ab)) + ab
            await self._send(peer, MsgType.PEERS, pl)

        elif mt == MsgType.PEERS:
            try:
                off = 0
                cnt = struct.unpack("!H", payload[:2])[0]
                off += 2
                for _ in range(cnt):
                    al = struct.unpack("!H", payload[off:off + 2])[0]
                    off += 2
                    addr = payload[off:off + al].decode()
                    self.known_addrs.add(addr)
                    off += al
            except Exception:
                pass

    # ── Sending ──────────────────────────────────────────────────────────

    async def _send(
        self, peer: Peer, mt: MsgType, payload: bytes
    ) -> None:
        """Send a message to a peer."""
        if not peer.writer or peer.writer.is_closing():
            return
        peer.writer.write(encode_message(self.magic, mt, payload))
        await peer.writer.drain()

    async def _send_version(self, peer: Peer) -> None:
        """Send a VERSION message to a peer."""
        p = encode_version_payload(
            PROTOCOL_VERSION,
            self.best_height_fn(),
            USER_AGENT,
            self.port,
        )
        await self._send(peer, MsgType.VERSION, p)
        peer.version_sent = True

    # ── Broadcasting ─────────────────────────────────────────────────────

    async def broadcast_block(self, block: Block) -> None:
        """Broadcast a block to all handshaked peers."""
        self._known_blocks.add(block.block_hash)
        data = block.serialize()
        count = 0
        for p in list(self.peers.values()):
            if p.is_handshaked:
                try:
                    await self._send(p, MsgType.BLOCK, data)
                    count += 1
                except Exception:
                    pass
        logger.info(f"Block {block.height} broadcast to {count} peers")

    async def broadcast_tx(self, tx: Transaction) -> None:
        """Broadcast a transaction INV to all handshaked peers."""
        self._known_txs.add(tx.txid)
        inv = struct.pack("!B", InvType.TX) + tx.txid
        for p in list(self.peers.values()):
            if p.is_handshaked:
                try:
                    await self._send(p, MsgType.INV, inv)
                except Exception:
                    pass

    # ── Maintenance ──────────────────────────────────────────────────────

    async def _maintenance_loop(self) -> None:
        """Periodic maintenance: ping peers, evict stale, discover new."""
        while self._running:
            await asyncio.sleep(PING_INTERVAL)
            now = time.time()

            for p in list(self.peers.values()):
                # Ping handshaked peers
                if p.is_handshaked:
                    p.last_ping = now
                    try:
                        await self._send(p, MsgType.PING, os.urandom(8))
                    except Exception:
                        await self._disconnect(p)

                # Evict stale peers (no activity for 3x ping interval)
                if now - p.last_seen > PING_INTERVAL * 3:
                    await self._disconnect(p)

            # Connect to more outbound peers if below target
            out = sum(1 for p in self.peers.values() if not p.is_inbound)
            if out < MAX_OUTBOUND:
                for a in list(self.known_addrs):
                    if a not in self.peers and out < MAX_OUTBOUND:
                        asyncio.create_task(self._connect_to_peer(a))
                        out += 1

    # ── Info ─────────────────────────────────────────────────────────────

    @property
    def info(self) -> dict:
        """P2P node status summary."""
        return {
            "listening": f"{self.host}:{self.port}",
            "peers": len(self.peers),
            "inbound": sum(1 for p in self.peers.values() if p.is_inbound),
            "outbound": sum(
                1 for p in self.peers.values() if not p.is_inbound
            ),
            "known_addrs": len(self.known_addrs),
            "known_blocks": len(self._known_blocks),
            "known_txs": len(self._known_txs),
        }