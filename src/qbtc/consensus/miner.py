"""
qBTC Miner v2 — HARDENED FOR PEER REVIEW
==========================================
SHA3-256d proof-of-work mining with Grover-resistant 64-bit nonce.

Mining Loop:
    1. Get current chain tip from blockchain
    2. Assemble candidate block:
       a. Create coinbase tx (reward + fees -> miner address)
       b. Select mempool transactions by fee rate
       c. Build Merkle tree
       d. Set header fields (prev_hash, bits, timestamp, etc.)
    3. Mine: increment 64-bit nonce until SHA3-256d(header) <= target
    4. Broadcast mined block to P2P network
    5. Repeat from step 1

Quantum Resistance:
    - 64-bit nonce -> 2^64 search space
    - Grover's algorithm: sqrt(2^64) = 2^32 quantum queries
    - This matches Bitcoin's classical 2^32 nonce security
    - SHA3-256d provides 128-bit post-quantum preimage security
    - QDE nonce randomization prevents quantum amplitude estimation
"""

from __future__ import annotations

import logging
import time
import threading
import os
import struct
from dataclasses import dataclass
from typing import Optional, Callable, List

from qbtc.core.constants import (
    INITIAL_BLOCK_REWARD,
    HALVING_INTERVAL,
    MAX_BLOCK_SIZE,
    COIN,
    TARGET_BLOCK_TIME,
    ConsensusMode,
)
from qbtc.core.block import Block, BlockHeader
from qbtc.core.transaction import Transaction, TxInput, TxOutput
from qbtc.crypto.hashing import (
    qhash,
    qhash_double,
    target_from_bits,
    hash_meets_target,
    qde_randomize_nonce,
)

logger = logging.getLogger("qbtc.miner")


# ═══════════════════════════════════════════════════════════════════════════
# MINING STATISTICS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class MiningStats:
    """Mining performance statistics."""
    blocks_mined: int = 0
    total_hashes: int = 0
    total_time: float = 0.0
    last_block_time: float = 0.0
    last_block_hashes: int = 0
    current_hashrate: float = 0.0
    total_reward: int = 0

    @property
    def avg_hashrate(self) -> float:
        if self.total_time == 0:
            return 0.0
        return self.total_hashes / self.total_time

    def __repr__(self) -> str:
        return (
            f"MiningStats(blocks={self.blocks_mined}, "
            f"hashrate={self.current_hashrate:.0f} H/s, "
            f"avg={self.avg_hashrate:.0f} H/s, "
            f"reward={self.total_reward / COIN:.8f} qBTC)"
        )


# ═══════════════════════════════════════════════════════════════════════════
# MINER
# ═══════════════════════════════════════════════════════════════════════════

class Miner:
    """SHA3-256d proof-of-work miner with QDE nonce randomization.

    The miner runs in a background thread to avoid blocking the
    asyncio event loop. New block templates are pushed via an
    event when the chain tip changes.
    """

    def __init__(
        self,
        blockchain,
        mempool,
        miner_address: bytes,
        consensus=None,
        miner_keypair=None,
        on_block_found: Optional[Callable] = None,
        num_threads: int = 1,
    ) -> None:
        self.blockchain = blockchain
        self.mempool = mempool
        self.miner_address = miner_address
        self.consensus = consensus
        self.miner_keypair = miner_keypair
        self.on_block_found = on_block_found
        self.num_threads = num_threads
        self.stats = MiningStats()

        self._running = False
        self._threads: List[threading.Thread] = []
        self._new_block_event = threading.Event()
        self._stop_event = threading.Event()

    # ── Properties ───────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start mining threads."""
        if self._running:
            return

        self._running = True
        self._stop_event.clear()

        for i in range(self.num_threads):
            t = threading.Thread(
                target=self._mining_thread,
                args=(i,),
                name=f"miner-{i}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

        logger.info(
            f"Miner started: {self.num_threads} thread(s), "
            f"address={self.miner_address.hex()[:16]}..."
        )

    def stop(self) -> None:
        """Stop all mining threads."""
        self._running = False
        self._stop_event.set()
        self._new_block_event.set()  # wake up threads

        for t in self._threads:
            t.join(timeout=5.0)
        self._threads.clear()

        logger.info(f"Miner stopped. {self.stats}")

    def notify_new_tip(self) -> None:
        """Notify miner that the chain tip has changed.

        Causes the miner to abandon the current candidate and
        rebuild a new block template on the new tip.
        """
        self._new_block_event.set()

    # ── Block Assembly ───────────────────────────────────────────────────

    def _assemble_candidate(self) -> Optional[Block]:
        """Build a candidate block from the current chain tip + mempool."""
        try:
            tip_height = self.blockchain.tip_height
            tip_hash = self.blockchain.tip_hash
            height = tip_height + 1

            # Calculate reward
            halvings = height // HALVING_INTERVAL
            if halvings >= 64:
                reward = 0
            else:
                reward = INITIAL_BLOCK_REWARD >> halvings

            # Select mempool transactions (reserve ~1200 bytes for coinbase + header)
            max_tx_size = MAX_BLOCK_SIZE - 1200
            mempool_txs = self.mempool.get_block_transactions(
                max_block_size=max_tx_size,
                max_tx_count=9999,
            )

            # Calculate total fees (simplified — uses mempool entry fees)
            total_fees = 0
            for tx in mempool_txs:
                entry = self.mempool.get_entry(tx.txid)
                if entry:
                    total_fees += entry.fee

            # Create coinbase transaction
            coinbase = Transaction.create_coinbase(
                height=height,
                reward=reward + total_fees,
                miner_pk_hash=self.miner_address,
                extra_data=b"/qBTC Miner v2/" + os.urandom(4),
            )

            # Get expected difficulty
            expected_bits = self.blockchain._calculate_next_bits(height)

            # Get the tip block for timestamp reference
            tip_block = self.blockchain.get_block_by_hash(tip_hash)
            min_timestamp = tip_block.header.timestamp + 1 if tip_block else 0

            # Build header
            header = BlockHeader(
                version=1,
                prev_block_hash=tip_hash,
                merkle_root=b"\x00" * 32,  # computed below
                timestamp=max(int(time.time()), min_timestamp),
                bits=expected_bits,
                nonce=0,
                height=height,
                stake_hash=b"\x00" * 32,
                consensus_flags=ConsensusMode.PURE_POW,
            )

            # Assemble block
            all_txs = [coinbase] + mempool_txs
            block = Block(header=header, transactions=all_txs)
            block.update_merkle_root()

            return block

        except Exception as e:
            logger.error(f"Block assembly failed: {e}")
            return None

    # ── Mining Loop ──────────────────────────────────────────────────────

    def _mining_thread(self, thread_id: int) -> None:
        """Main mining loop for a single thread."""
        logger.debug(f"Mining thread {thread_id} started")

        while self._running:
            # Assemble candidate block
            candidate = self._assemble_candidate()
            if candidate is None:
                time.sleep(1)
                continue

            target = target_from_bits(candidate.header.bits)
            header = candidate.header

            logger.info(
                f"[Thread {thread_id}] Mining block #{header.height} "
                f"(difficulty={header.difficulty:.4f}, "
                f"txs={candidate.tx_count})"
            )

            # QDE: Randomize starting nonce instead of starting from 0
            miner_key_id = self.miner_address[:20]
            start_nonce = qde_randomize_nonce(
                miner_key_id=miner_key_id,
                prev_hash=header.prev_block_hash,
                timestamp=header.timestamp,
            )

            # Partition nonce space across threads
            thread_offset = thread_id * (2**60)
            nonce = (start_nonce + thread_offset) % (2**64)

            start_time = time.time()
            hashes = 0
            self._new_block_event.clear()

            while self._running:
                # Check if we should restart (new tip received)
                if self._new_block_event.is_set():
                    logger.debug(f"[Thread {thread_id}] New tip — restarting")
                    break

                # Try nonce
                header.nonce = nonce
                block_hash = header.block_hash
                hashes += 1

                if hash_meets_target(block_hash, target):
                    # BLOCK FOUND!
                    elapsed = time.time() - start_time
                    hashrate = hashes / max(elapsed, 0.001)

                    logger.info(
                        f"BLOCK FOUND! height={header.height}, "
                        f"nonce={nonce}, "
                        f"hash={block_hash.hex()[:32]}..., "
                        f"hashes={hashes}, "
                        f"time={elapsed:.2f}s, "
                        f"hashrate={hashrate:.0f} H/s"
                    )

                    # Update stats
                    reward = candidate.transactions[0].total_output
                    self.stats.blocks_mined += 1
                    self.stats.total_hashes += hashes
                    self.stats.total_time += elapsed
                    self.stats.last_block_time = elapsed
                    self.stats.last_block_hashes = hashes
                    self.stats.current_hashrate = hashrate
                    self.stats.total_reward += reward

                    # Submit block
                    accepted, msg = self.blockchain.add_block(candidate)
                    if accepted:
                        logger.info(
                            f"Block #{header.height} accepted into chain"
                        )
                        # Notify callback (broadcasts to network)
                        if self.on_block_found:
                            self.on_block_found(candidate)
                        # Remove confirmed transactions from mempool
                        confirmed = [tx.txid for tx in candidate.transactions]
                        self.mempool.remove_confirmed(confirmed)
                    else:
                        logger.warning(f"Mined block rejected: {msg}")

                    break  # Start mining next block

                # Increment nonce (wrapping at 2^64)
                nonce = (nonce + 1) % (2**64)

                # Log hashrate periodically
                if hashes % 100_000 == 0:
                    elapsed = time.time() - start_time
                    hashrate = hashes / max(elapsed, 0.001)
                    self.stats.current_hashrate = hashrate
                    logger.debug(
                        f"[Thread {thread_id}] "
                        f"{hashes} hashes, "
                        f"{hashrate:.0f} H/s"
                    )

    # ── Info ─────────────────────────────────────────────────────────────

    @property
    def info(self) -> dict:
        return {
            "running": self._running,
            "threads": self.num_threads,
            "blocks_mined": self.stats.blocks_mined,
            "hashrate": self.stats.current_hashrate,
            "avg_hashrate": self.stats.avg_hashrate,
            "total_reward": self.stats.total_reward / COIN,
        }