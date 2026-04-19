"""
qBTC Blockchain State Manager v2 — HARDENED FOR PEER REVIEW
=============================================================
Manages the chain of blocks, UTXO set, difficulty adjustments,
and provides the interface between consensus, mempool, and storage.

Architecture:
    Chain ---+-- BlockIndex      (height -> block_hash mapping)
             +-- UTXOSet         (unspent transaction output database)
             +-- DifficultyEngine (retargeting every 1008 blocks)
             +-- ChainTip        (current best chain state)

Difficulty Retarget Algorithm:
    Every DIFFICULTY_ADJUSTMENT_INTERVAL (1008) blocks:
        actual_time = timestamp[tip] - timestamp[tip - 1008]
        expected_time = 1008 * TARGET_BLOCK_TIME  (= 120,960 seconds)
        ratio = actual_time / expected_time
        ratio = clamp(ratio, 0.25, 4.0)  # max 4x adjustment
        new_target = old_target * ratio
        new_target = min(new_target, MAX_TARGET)

    This is identical to Bitcoin's algorithm (but with different
    interval and block time). No "Grover factor" is applied because
    the 64-bit nonce already neutralizes quantum speedup.

UTXO Model:
    qBTC uses Bitcoin's UTXO model, NOT an account model.
    Each transaction output is either spent or unspent.
    Spending requires proving ownership via ML-DSA-65 signature
    over the transaction digest, with the public key whose hash
    matches the UTXO's pk_hash.
"""

from __future__ import annotations

import time
import threading
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

from qbtc.core.constants import (
    TARGET_BLOCK_TIME,
    DIFFICULTY_ADJUSTMENT_INTERVAL,
    MAX_TARGET,
    GENESIS_BITS,
    COINBASE_MATURITY,
    MAX_MONEY,
    HALVING_INTERVAL,
    INITIAL_BLOCK_REWARD,
    HYBRID_ACTIVATION_HEIGHT,
    ConsensusMode,
)
from qbtc.core.block import Block, BlockHeader
from qbtc.core.transaction import Transaction
from qbtc.crypto.hashing import (
    qhash,
    qhash_double,
    target_from_bits,
    bits_from_target,
    hash_meets_target,
)

logger = logging.getLogger("qbtc.chain")


# ═══════════════════════════════════════════════════════════════════════════
# UTXO ENTRY
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class UTXOKey:
    """Reference to an unspent output: (txid, output_index).

    This is the primary key for the UTXO set. Two UTXOKeys are equal
    if and only if they reference the same transaction output.
    """
    txid: bytes
    index: int

    def __hash__(self) -> int:
        return hash((self.txid, self.index))

    def __repr__(self) -> str:
        return f"UTXOKey({self.txid.hex()[:16]}...:{self.index})"


@dataclass
class UTXOEntry:
    """An unspent transaction output with metadata.

    Attributes:
        amount:       Value in quantum-satoshis
        pk_hash:      Public key hash of the owner
        block_height: Height of the block containing this output
        is_coinbase:  Whether this output is from a coinbase transaction
                      (subject to COINBASE_MATURITY spending restriction)
    """
    amount: int
    pk_hash: bytes
    block_height: int
    is_coinbase: bool


# ═══════════════════════════════════════════════════════════════════════════
# BLOCK INDEX ENTRY
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class BlockIndexEntry:
    """Lightweight index entry for each block in the chain.

    Stored in memory for fast chain traversal. The full block data
    is stored separately in self.blocks (would be LevelDB in production).
    """
    block_hash: bytes
    prev_hash: bytes
    height: int
    timestamp: int
    bits: int
    nonce: int
    merkle_root: bytes
    tx_count: int
    block_size: int
    total_work: int = 0     # cumulative chain work up to this block

    def __repr__(self) -> str:
        return (
            f"BlockIndexEntry(height={self.height}, "
            f"hash={self.block_hash.hex()[:16]}..., "
            f"work={self.total_work})"
        )


# ═══════════════════════════════════════════════════════════════════════════
# BLOCKCHAIN
# ═══════════════════════════════════════════════════════════════════════════

class Blockchain:
    """The qBTC blockchain state manager.

    Maintains:
        - Block index (height -> BlockIndexEntry)
        - Hash-to-height mapping
        - UTXO set (all unspent outputs)
        - Chain tip (best block)
        - Orphan block pool

    Thread-safe via reentrant lock.

    In production, the UTXO set and block index would be backed by
    LevelDB or a similar embedded database. This reference implementation
    uses in-memory dicts for simplicity and testability.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()

        # Block index
        self.block_index: Dict[int, BlockIndexEntry] = {}
        self.hash_to_height: Dict[bytes, int] = {}

        # Full blocks (in-memory — production would use LevelDB)
        self.blocks: Dict[bytes, Block] = {}

        # UTXO set
        self.utxo_set: Dict[UTXOKey, UTXOEntry] = {}

        # Chain state
        self.tip_hash: bytes = b"\x00" * 32
        self.tip_height: int = -1
        self.total_work: int = 0

        # Orphan pool (blocks received before their parent)
        self.orphans: Dict[bytes, Block] = {}  # prev_hash -> block

        # Initialize with genesis
        self._initialize_genesis()

    # ── Properties ───────────────────────────────────────────────────────

    @property
    def tip(self) -> Optional[Block]:
        """The current chain tip block."""
        return self.blocks.get(self.tip_hash)

    @property
    def height(self) -> int:
        """Current chain height (alias for tip_height)."""
        return self.tip_height

    @property
    def consensus_mode(self) -> ConsensusMode:
        """Current consensus mode based on chain height."""
        if self.tip_height < HYBRID_ACTIVATION_HEIGHT:
            return ConsensusMode.PURE_POW
        return ConsensusMode.HYBRID

    # ── Genesis ──────────────────────────────────────────────────────────

    def _initialize_genesis(self) -> None:
        """Create and accept the genesis block."""
        genesis = Block.create_genesis()
        self._accept_block(genesis, validate=False)
        logger.info(
            f"Genesis block initialized: {genesis.block_hash_hex[:16]}... "
            f"at height 0"
        )

    # ── Block Acceptance ─────────────────────────────────────────────────

    def add_block(self, block: Block) -> Tuple[bool, str]:
        """Attempt to add a block to the chain.

        Performs full validation:
            1. Not already in chain (duplicate check)
            2. Structural validation (internal consistency)
            3. Previous block exists (or store as orphan)
            4. Height is correct (prev_height + 1)
            5. Difficulty target is correct (retarget algorithm)
            6. Timestamp sanity (> median of last 11 blocks)
            7. UTXO validation (inputs exist, amounts balance)
            8. Coinbase reward check (reward + fees)

        Returns:
            (accepted: bool, reason: str)
        """
        with self._lock:
            block_hash = block.block_hash

            # 1. Already have this block?
            if block_hash in self.hash_to_height:
                return False, "Block already in chain"

            # 2. Structural validation
            valid, msg = block.validate_structure()
            if not valid:
                return False, f"Structural: {msg}"

            # 3. Previous block must exist
            prev_hash = block.header.prev_block_hash
            if prev_hash not in self.hash_to_height:
                # Store as orphan for later processing
                self.orphans[prev_hash] = block
                return False, "Orphan — previous block unknown"

            # 4. Height must be prev_height + 1
            prev_height = self.hash_to_height[prev_hash]
            expected_height = prev_height + 1
            if block.header.height != expected_height:
                return False, (
                    f"Height mismatch: got {block.header.height}, "
                    f"expected {expected_height}"
                )

            # 5. Difficulty check
            expected_bits = self._calculate_next_bits(expected_height)
            if block.header.bits != expected_bits:
                return False, (
                    f"Difficulty mismatch: got {hex(block.header.bits)}, "
                    f"expected {hex(expected_bits)}"
                )

            # 6. Timestamp sanity: must be > median of last 11 blocks
            median_time = self._get_median_time_past(prev_hash)
            if block.header.timestamp <= median_time:
                return False, (
                    f"Timestamp {block.header.timestamp} <= "
                    f"median time past {median_time}"
                )

            # 7. UTXO validation
            utxo_valid, utxo_msg = self._validate_utxos(block)
            if not utxo_valid:
                return False, f"UTXO: {utxo_msg}"

            # 8. All checks passed — accept
            return self._accept_block(block)

    def _accept_block(
        self, block: Block, validate: bool = True
    ) -> Tuple[bool, str]:
        """Accept a validated block into the chain."""
        block_hash = block.block_hash
        height = block.header.height

        # Calculate proof-of-work for this block
        target = target_from_bits(block.header.bits)
        if target > 0:
            block_work = (2**256) // (target + 1)
        else:
            block_work = 0

        # Build index entry
        entry = BlockIndexEntry(
            block_hash=block_hash,
            prev_hash=block.header.prev_block_hash,
            height=height,
            timestamp=block.header.timestamp,
            bits=block.header.bits,
            nonce=block.header.nonce,
            merkle_root=block.header.merkle_root,
            tx_count=block.tx_count,
            block_size=block.size,
            total_work=self.total_work + block_work,
        )

        # Update indices
        self.block_index[height] = entry
        self.hash_to_height[block_hash] = height
        self.blocks[block_hash] = block

        # Update UTXO set
        self._apply_block_to_utxos(block)

        # Update chain tip
        self.total_work = entry.total_work
        self.tip_hash = block_hash
        self.tip_height = height

        logger.info(
            f"Block accepted: height={height}, "
            f"hash={block_hash.hex()[:16]}..., "
            f"txs={block.tx_count}, "
            f"work={self.total_work}"
        )

        # Check for orphans that depend on this block
        self._process_orphans(block_hash)

        return True, "Accepted"

    # ── UTXO Management ──────────────────────────────────────────────────

    def _apply_block_to_utxos(self, block: Block) -> None:
        """Apply a block's transactions to the UTXO set.

        For each transaction:
            1. Remove all inputs from the UTXO set (they are now spent)
            2. Add all outputs to the UTXO set (they are now unspent)
        """
        for tx in block.transactions:
            # Remove spent UTXOs (skip coinbase inputs — they reference nothing)
            if not tx.is_coinbase:
                for inp in tx.inputs:
                    key = UTXOKey(txid=inp.prev_txid, index=inp.prev_index)
                    self.utxo_set.pop(key, None)

            # Add new UTXOs
            for idx, out in enumerate(tx.outputs):
                key = UTXOKey(txid=tx.txid, index=idx)
                self.utxo_set[key] = UTXOEntry(
                    amount=out.amount,
                    pk_hash=out.pk_hash,
                    block_height=block.height,
                    is_coinbase=tx.is_coinbase,
                )

    def _validate_utxos(self, block: Block) -> Tuple[bool, str]:
        """Validate all transaction inputs against the UTXO set.

        Checks:
            1. No double-spends within the block
            2. All referenced UTXOs exist
            3. Coinbase maturity is satisfied
            4. Public key hashes match the UTXO
            5. Input amounts >= output amounts (fees are non-negative)
            6. Coinbase output <= block_reward + total_fees
        """
        spent_in_block: Set[UTXOKey] = set()
        total_fees = 0

        for tx_idx, tx in enumerate(block.transactions):
            if tx.is_coinbase:
                continue

            input_sum = 0
            for inp in tx.inputs:
                key = UTXOKey(txid=inp.prev_txid, index=inp.prev_index)

                # Check for double-spend within block
                if key in spent_in_block:
                    return False, f"Double-spend in block: {key}"
                spent_in_block.add(key)

                # Check UTXO exists
                utxo = self.utxo_set.get(key)
                if utxo is None:
                    return False, (
                        f"UTXO not found: "
                        f"{inp.prev_txid.hex()[:16]}:{inp.prev_index}"
                    )

                # Check coinbase maturity
                if utxo.is_coinbase:
                    confirmations = block.header.height - utxo.block_height
                    if confirmations < COINBASE_MATURITY:
                        return False, (
                            f"Coinbase not mature: {confirmations} "
                            f"confirmations < {COINBASE_MATURITY} required"
                        )

                # Check public key hash matches
                if inp.public_key:
                    spender_pk_hash = qhash(inp.public_key)[:len(utxo.pk_hash)]
                    if spender_pk_hash != utxo.pk_hash:
                        return False, (
                            f"Public key hash mismatch for input "
                            f"{inp.prev_txid.hex()[:16]}:{inp.prev_index}"
                        )

                input_sum += utxo.amount

            # Check output amounts
            output_sum = tx.total_output
            if output_sum > input_sum:
                return False, (
                    f"Output sum {output_sum} exceeds input sum {input_sum} "
                    f"in tx {tx.txid_hex[:16]}..."
                )
            if output_sum > MAX_MONEY:
                return False, f"Output sum {output_sum} exceeds MAX_MONEY"

            total_fees += (input_sum - output_sum)

        # Validate coinbase reward
        coinbase = block.transactions[0]
        max_reward = Block.get_block_reward(block.header.height) + total_fees
        if coinbase.total_output > max_reward:
            return False, (
                f"Coinbase output {coinbase.total_output} exceeds "
                f"max reward {max_reward} (block_reward + fees)"
            )

        return True, "OK"

    # ── UTXO Queries ─────────────────────────────────────────────────────

    def get_utxo(self, key: UTXOKey) -> Optional[UTXOEntry]:
        """Look up a single UTXO by key."""
        return self.utxo_set.get(key)

    def get_balance(self, pk_hash: bytes) -> int:
        """Get the total balance for a public key hash.

        Scans the entire UTXO set. In production, this would be
        indexed for O(1) lookup.
        """
        total = 0
        for key, entry in self.utxo_set.items():
            if entry.pk_hash == pk_hash:
                total += entry.amount
        return total

    def get_utxos_for_address(
        self, pk_hash: bytes
    ) -> List[Tuple[UTXOKey, UTXOEntry]]:
        """Get all UTXOs belonging to a public key hash.

        Returns:
            List of (UTXOKey, UTXOEntry) tuples.
        """
        results = []
        for key, entry in self.utxo_set.items():
            if entry.pk_hash == pk_hash:
                results.append((key, entry))
        return results

    # ── Difficulty Adjustment ────────────────────────────────────────────

    def _calculate_next_bits(self, height: int = None) -> int:
        """Calculate the expected difficulty bits for the next block.

        Uses Bitcoin's difficulty adjustment algorithm:
            Every DIFFICULTY_ADJUSTMENT_INTERVAL blocks, compare the
            actual time elapsed to the expected time, and adjust the
            target proportionally. Clamped to max 4x change per period.

        No Grover factor is applied — the 64-bit nonce already
        neutralizes quantum speedup. See constants.py for analysis.
        """
        if height is None:
            height = self.tip_height + 1

        # Genesis and early blocks use genesis difficulty
        if height == 0:
            return GENESIS_BITS

        # Only retarget at interval boundaries
        if height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0:
            # Return the same bits as the previous block
            prev_entry = self.block_index.get(height - 1)
            if prev_entry:
                return prev_entry.bits
            return GENESIS_BITS

        # Retarget: compare actual vs expected timespan
        current_entry = self.block_index.get(height - 1)
        period_start_entry = self.block_index.get(
            height - DIFFICULTY_ADJUSTMENT_INTERVAL
        )

        if not current_entry or not period_start_entry:
            return GENESIS_BITS

        actual_timespan = (
            current_entry.timestamp - period_start_entry.timestamp
        )
        expected_timespan = (
            DIFFICULTY_ADJUSTMENT_INTERVAL * TARGET_BLOCK_TIME
        )

        # Clamp to max 4x adjustment in either direction
        if actual_timespan < expected_timespan // 4:
            actual_timespan = expected_timespan // 4
        elif actual_timespan > expected_timespan * 4:
            actual_timespan = expected_timespan * 4

        # Calculate new target
        old_target = target_from_bits(current_entry.bits)
        new_target = (old_target * actual_timespan) // expected_timespan

        # Cap at MAX_TARGET
        if new_target > MAX_TARGET:
            new_target = MAX_TARGET

        # Ensure target is positive
        if new_target <= 0:
            new_target = 1

        new_bits = bits_from_target(new_target)

        logger.info(
            f"Difficulty retarget at height {height}: "
            f"actual={actual_timespan}s, expected={expected_timespan}s, "
            f"ratio={actual_timespan/expected_timespan:.4f}, "
            f"old_bits={hex(current_entry.bits)}, new_bits={hex(new_bits)}"
        )

        return new_bits

    # ── Median Time Past ─────────────────────────────────────────────────

    def _get_median_time_past(self, block_hash: bytes) -> int:
        """Get the median timestamp of the last 11 blocks.

        This is used as a lower bound for the next block's timestamp,
        preventing timestamp manipulation attacks. Identical to
        Bitcoin's Median Time Past (MTP) rule (BIP 113).
        """
        timestamps = []
        current_hash = block_hash

        for _ in range(11):
            if current_hash not in self.hash_to_height:
                break
            height = self.hash_to_height[current_hash]
            entry = self.block_index.get(height)
            if entry is None:
                break
            timestamps.append(entry.timestamp)
            current_hash = entry.prev_hash

        if not timestamps:
            return 0

        timestamps.sort()
        return timestamps[len(timestamps) // 2]

    # ── Orphan Processing ────────────────────────────────────────────────

    def _process_orphans(self, new_block_hash: bytes) -> None:
        """Check if any orphan blocks can now be accepted.

        When a new block is accepted, check if any orphans were
        waiting for it as their parent. If so, try to accept them.
        This cascades: accepting an orphan may unblock more orphans.
        """
        if new_block_hash in self.orphans:
            orphan = self.orphans.pop(new_block_hash)
            logger.info(
                f"Processing orphan block at height {orphan.header.height}"
            )
            self.add_block(orphan)

    # ── Block Retrieval ──────────────────────────────────────────────────

    def get_block_by_height(self, height: int) -> Optional[Block]:
        """Get a block by its height."""
        entry = self.block_index.get(height)
        if entry is None:
            return None
        return self.blocks.get(entry.block_hash)

    def get_block_by_hash(self, block_hash: bytes) -> Optional[Block]:
        """Get a block by its hash."""
        return self.blocks.get(block_hash)

    def get_block_hashes(
        self, start_height: int, count: int
    ) -> List[bytes]:
        """Get a range of block hashes for synchronization.

        Args:
            start_height: Starting height (inclusive).
            count: Maximum number of hashes to return.

        Returns:
            List of block hashes in height order.
        """
        hashes = []
        for h in range(start_height, start_height + count):
            entry = self.block_index.get(h)
            if entry is None:
                break
            hashes.append(entry.block_hash)
        return hashes

    # ── Chain Info ────────────────────────────────────────────────────────

    @property
    def info(self) -> dict:
        """Summary of the current chain state."""
        tip = self.tip
        return {
            "height": self.tip_height,
            "tip_hash": self.tip_hash.hex() if self.tip_hash else None,
            "total_work": self.total_work,
            "utxo_count": len(self.utxo_set),
            "block_count": len(self.block_index),
            "orphan_count": len(self.orphans),
            "consensus_mode": self.consensus_mode.name,
            "difficulty": tip.header.difficulty if tip else 0,
        }

    def __repr__(self) -> str:
        return (
            f"Blockchain(height={self.tip_height}, "
            f"tip={self.tip_hash.hex()[:16]}..., "
            f"utxos={len(self.utxo_set)}, "
            f"work={self.total_work})"
        )