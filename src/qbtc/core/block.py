"""
qBTC Block Structure v2 — HARDENED FOR PEER REVIEW
====================================================
Post-quantum block with SHA3-256 double-hash proof-of-work.

Block Wire Format:
    +--------------------------------------------------------------+
    |  HEADER (122 bytes fixed)                                    |
    |    +- version          : uint32      (4 bytes)               |
    |    +- prev_block_hash  : bytes       (32 bytes)              |
    |    +- merkle_root      : bytes       (32 bytes)              |
    |    +- timestamp        : uint32      (4 bytes)               |
    |    +- bits             : uint32      (4 bytes, compact target)|
    |    +- nonce            : uint64      (8 bytes, Grover-safe)  |
    |    +- height           : uint32      (4 bytes)               |
    |    +- stake_hash       : bytes       (32 bytes, PoS kernel)  |
    |    +- consensus_flags  : uint16      (2 bytes)               |
    |  BODY                                                        |
    |    +- tx_count         : varint                              |
    |    +- transactions[]   : Transaction[]                       |
    +--------------------------------------------------------------+

Header Size Breakdown (122 bytes):
    version:          4   bytes
    prev_block_hash: 32   bytes
    merkle_root:     32   bytes
    timestamp:        4   bytes
    bits:             4   bytes
    nonce:            8   bytes  (64-bit, vs Bitcoin's 32-bit)
    height:           4   bytes  (explicit, for SPV light clients)
    stake_hash:      32   bytes  (hybrid PoS kernel hash)
    consensus_flags:  2   bytes  (mode signaling: PoW/hybrid/PoS)
    ────────────────────────────
    TOTAL:          122   bytes  (vs Bitcoin's 80 bytes)

The extra 42 bytes accommodate:
  - 64-bit nonce (vs 32-bit): Grover's algorithm on a 32-bit nonce
    requires only sqrt(2^32) = 2^16 quantum operations (trivial).
    A 64-bit nonce requires sqrt(2^64) = 2^32 operations, matching
    Bitcoin's classical security level.
  - 32-byte stake_hash for hybrid PoS kernel commitment.
  - 2-byte consensus_flags for signaling consensus mode transitions.
  - Explicit height in header for O(1) SPV height verification.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional

from qbtc.core.constants import (
    GENESIS_PREV_HASH,
    GENESIS_TIMESTAMP,
    GENESIS_BITS,
    GENESIS_COINBASE_MSG,
    INITIAL_BLOCK_REWARD,
    HALVING_INTERVAL,
    MAX_BLOCK_SIZE,
    BLOCK_HEADER_SIZE,
    COIN,
    ConsensusMode,
)
from qbtc.core.transaction import Transaction, TxInput, TxOutput, encode_varint, decode_varint
from qbtc.crypto.hashing import qhash, qhash_double, qhash_merkle, target_from_bits, hash_meets_target


# ═══════════════════════════════════════════════════════════════════════════
# BLOCK HEADER — 122 bytes serialized
# ═══════════════════════════════════════════════════════════════════════════

HEADER_SIZE = BLOCK_HEADER_SIZE  # 122 bytes


@dataclass
class BlockHeader:
    """qBTC block header — 122 bytes serialized.

    The block hash is SHA3-256d(header_bytes), providing 128-bit
    post-quantum preimage security against Grover's algorithm.

    Field Layout (all integers are little-endian unless noted):
        Offset  Size  Field
        ------  ----  -----
        0       4     version
        4       32    prev_block_hash
        36      32    merkle_root
        68      4     timestamp (Unix epoch seconds)
        72      4     bits (compact difficulty target, nBits format)
        76      8     nonce (64-bit, Grover-resistant search space)
        84      4     height (explicit for SPV proofs)
        88      32    stake_hash (PoS kernel hash, all zeros in pure PoW)
        120     2     consensus_flags (0=PoW, 1=hybrid, 2=PoS)
        ------  ----
        122     TOTAL
    """
    version: int = 1
    prev_block_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    merkle_root: bytes = field(default_factory=lambda: b"\x00" * 32)
    timestamp: int = 0
    bits: int = 0x1d00ffff           # compact difficulty target
    nonce: int = 0                    # 64-bit nonce (Grover-resistant)
    height: int = 0
    stake_hash: bytes = field(default_factory=lambda: b"\x00" * 32)
    consensus_flags: int = 0          # 0 = pure PoW, 1 = hybrid, 2 = pure PoS

    def serialize(self) -> bytes:
        """Serialize header to exactly 122 bytes.

        Raises:
            AssertionError: if the serialized output is not exactly 122 bytes.
        """
        data = (
            struct.pack("<I", self.version)          # 4
            + self.prev_block_hash                    # 32
            + self.merkle_root                        # 32
            + struct.pack("<I", self.timestamp)       # 4
            + struct.pack("<I", self.bits)            # 4
            + struct.pack("<Q", self.nonce)           # 8
            + struct.pack("<I", self.height)          # 4
            + self.stake_hash                         # 32
            + struct.pack("<H", self.consensus_flags) # 2
        )                                             # = 122
        assert len(data) == HEADER_SIZE, (
            f"Header serialization error: expected {HEADER_SIZE} bytes, "
            f"got {len(data)}"
        )
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "BlockHeader":
        """Deserialize header from 122 bytes.

        Args:
            data: At least 122 bytes of raw header data.

        Returns:
            BlockHeader instance.
        """
        if len(data) < HEADER_SIZE:
            raise ValueError(
                f"Header data too short: need {HEADER_SIZE} bytes, "
                f"got {len(data)}"
            )
        version = struct.unpack("<I", data[0:4])[0]
        prev_block_hash = data[4:36]
        merkle_root = data[36:68]
        timestamp = struct.unpack("<I", data[68:72])[0]
        bits = struct.unpack("<I", data[72:76])[0]
        nonce = struct.unpack("<Q", data[76:84])[0]
        height = struct.unpack("<I", data[84:88])[0]
        stake_hash = data[88:120]
        consensus_flags = struct.unpack("<H", data[120:122])[0]
        return cls(
            version=version,
            prev_block_hash=prev_block_hash,
            merkle_root=merkle_root,
            timestamp=timestamp,
            bits=bits,
            nonce=nonce,
            height=height,
            stake_hash=stake_hash,
            consensus_flags=consensus_flags,
        )

    @property
    def block_hash(self) -> bytes:
        """SHA3-256d of the serialized header.

        This is the block's unique identifier and the value that
        must satisfy the proof-of-work difficulty target.
        """
        return qhash_double(self.serialize())

    @property
    def block_hash_hex(self) -> str:
        """Block hash as lowercase hex string."""
        return self.block_hash.hex()

    @property
    def target(self) -> int:
        """Decode the compact 'bits' field into a 256-bit target integer."""
        return target_from_bits(self.bits)

    @property
    def difficulty(self) -> float:
        """Difficulty relative to genesis target.

        difficulty = genesis_target / current_target
        Higher difficulty = harder to mine = lower target value.
        """
        genesis_target = target_from_bits(GENESIS_BITS)
        current_target = self.target
        if current_target == 0:
            return float("inf")
        return genesis_target / current_target

    def meets_target(self) -> bool:
        """Check if this header's hash satisfies the difficulty target.

        Returns:
            True if SHA3-256d(header) <= target.
        """
        return hash_meets_target(self.block_hash, self.target)

    def __repr__(self) -> str:
        return (
            f"BlockHeader(height={self.height}, "
            f"hash={self.block_hash_hex[:16]}..., "
            f"difficulty={self.difficulty:.2f})"
        )


# ═══════════════════════════════════════════════════════════════════════════
# FULL BLOCK
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Block:
    """A complete qBTC block: header + transactions.

    Validation Rules:
        1. Header hash must meet the difficulty target
        2. Merkle root must match the computed Merkle tree of txids
        3. First transaction must be a valid coinbase
        4. Coinbase reward must not exceed block_reward + fees
        5. All non-coinbase inputs must have valid PQ signatures
        6. Block size must not exceed MAX_BLOCK_SIZE
        7. No double-spends within the block
        8. Timestamp must be > median of last 11 blocks
        9. Only one coinbase transaction allowed (must be first)
        10. All output amounts must be non-negative and <= MAX_MONEY
    """
    header: BlockHeader = field(default_factory=BlockHeader)
    transactions: List[Transaction] = field(default_factory=list)

    @property
    def block_hash(self) -> bytes:
        """Block hash (from header)."""
        return self.header.block_hash

    @property
    def block_hash_hex(self) -> str:
        """Block hash as hex string."""
        return self.header.block_hash_hex

    @property
    def height(self) -> int:
        """Block height (from header)."""
        return self.header.height

    @property
    def tx_count(self) -> int:
        """Number of transactions in this block."""
        return len(self.transactions)

    @property
    def size(self) -> int:
        """Total serialized size in bytes."""
        return len(self.serialize())

    @property
    def weight(self) -> int:
        """Total block weight (with signature discount).

        Non-signature bytes count as 4 weight units each.
        Signature bytes count as 1 weight unit each (0.25x discount).
        """
        total = HEADER_SIZE * 4  # header is all non-signature
        for tx in self.transactions:
            total += tx.weight
        return total

    # ── Merkle Root ──────────────────────────────────────────────────────

    def compute_merkle_root(self) -> bytes:
        """Compute Merkle root from all transaction IDs."""
        if not self.transactions:
            return b"\x00" * 32
        tx_hashes = [tx.txid for tx in self.transactions]
        return qhash_merkle(tx_hashes)

    def update_merkle_root(self) -> None:
        """Recompute and set the header's merkle_root."""
        self.header.merkle_root = self.compute_merkle_root()

    def verify_merkle_root(self) -> bool:
        """Check that the header's merkle_root matches the transactions."""
        return self.header.merkle_root == self.compute_merkle_root()

    # ── Block Reward ─────────────────────────────────────────────────────

    @staticmethod
    def get_block_reward(height: int) -> int:
        """Calculate the block reward at a given height.

        Halves every HALVING_INTERVAL blocks, identical to Bitcoin.
        After 64 halvings, the reward is zero (all coins mined).

        Schedule:
            Height 0 - 209,999:        50 qBTC
            Height 210,000 - 419,999:   25 qBTC
            Height 420,000 - 629,999:   12.5 qBTC
            ...
            Height >= 13,440,000:       0 qBTC (all 21M mined)
        """
        halvings = height // HALVING_INTERVAL
        if halvings >= 64:
            return 0
        return INITIAL_BLOCK_REWARD >> halvings

    # ── Serialization ────────────────────────────────────────────────────

    def serialize(self) -> bytes:
        """Serialize the full block (header + transactions).

        Format:
            [122 bytes: header]
            [varint: tx_count]
            For each transaction:
                [varint: tx_byte_length]
                [tx_bytes]
        """
        parts = [self.header.serialize()]
        parts.append(encode_varint(len(self.transactions)))
        for tx in self.transactions:
            tx_bytes = tx.serialize()
            parts.append(encode_varint(len(tx_bytes)))
            parts.append(tx_bytes)
        return b"".join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> "Block":
        """Deserialize a full block from wire format."""
        header = BlockHeader.deserialize(data[:HEADER_SIZE])
        offset = HEADER_SIZE

        tx_count, offset = decode_varint(data, offset)
        transactions = []
        for _ in range(tx_count):
            tx_len, offset = decode_varint(data, offset)
            tx_data = data[offset:offset + tx_len]
            tx = Transaction.deserialize(tx_data)
            transactions.append(tx)
            offset += tx_len

        return cls(header=header, transactions=transactions)

    # ── Validation ───────────────────────────────────────────────────────

    def validate_structure(self) -> tuple[bool, str]:
        """Perform structural validation (no UTXO context needed).

        This checks the block's internal consistency without access
        to the blockchain state. UTXO validation is done separately
        by the Blockchain.add_block() method.

        Returns:
            (is_valid, error_message)
        """
        # 1. Block size check
        block_size = self.size
        if block_size > MAX_BLOCK_SIZE:
            return False, f"Block size {block_size} exceeds max {MAX_BLOCK_SIZE}"

        # 2. Must have at least one transaction (coinbase)
        if not self.transactions:
            return False, "Block has no transactions"

        # 3. First transaction must be coinbase
        if not self.transactions[0].is_coinbase:
            return False, "First transaction is not coinbase"

        # 4. Only one coinbase allowed
        for i in range(1, len(self.transactions)):
            if self.transactions[i].is_coinbase:
                return False, f"Multiple coinbase transactions (index {i})"

        # 5. Merkle root must match
        if not self.verify_merkle_root():
            return False, "Merkle root mismatch"

        # 6. Proof-of-work check
        if not self.header.meets_target():
            return False, (
                f"Block hash does not meet target: "
                f"hash={self.header.block_hash_hex[:32]}..., "
                f"target=0x{self.header.target:064x}"
            )

        # 7. Coinbase reward check
        max_reward = self.get_block_reward(self.header.height)
        # Total fees would need UTXO context, so we check coinbase
        # output doesn't exceed reward + theoretical max fees
        coinbase_output = self.transactions[0].total_output
        if coinbase_output > max_reward + MAX_BLOCK_SIZE * 100:
            return False, (
                f"Coinbase output {coinbase_output} exceeds maximum possible "
                f"(reward={max_reward} + max_fees)"
            )

        # 8. Check for duplicate transactions
        seen_txids: set = set()
        for tx in self.transactions:
            txid = tx.txid
            if txid in seen_txids:
                return False, f"Duplicate transaction: {txid.hex()[:16]}..."
            seen_txids.add(txid)

        # 9. Timestamp sanity (not more than 2 hours in the future)
        max_future = int(time.time()) + 7200
        if self.header.timestamp > max_future:
            return False, (
                f"Timestamp {self.header.timestamp} is more than "
                f"2 hours in the future"
            )

        return True, "OK"

    # ── Genesis Block ────────────────────────────────────────────────────

    @classmethod
    def create_genesis(cls) -> "Block":
        """Create the genesis block.

        The genesis block has:
            - prev_hash = 0x00...00 (32 zero bytes)
            - A coinbase transaction with the genesis message
            - Timestamp: 2025-04-19T00:00:00Z (1745024400)
            - Initial difficulty: 0x1d00ffff
            - Height: 0
            - Nonce: found by mining the genesis block

        The coinbase message is embedded as a timestamp proof:
            "qBTC/2025-04-19/Post-Quantum Dawn: The SHA3 chain begins"
        """
        # Genesis coinbase
        genesis_coinbase = Transaction.create_coinbase(
            height=0,
            reward=INITIAL_BLOCK_REWARD,
            miner_pk_hash=qhash(b"qBTC-genesis-miner")[:20],
            extra_data=GENESIS_COINBASE_MSG.encode("utf-8"),
        )

        # Genesis header
        genesis_header = BlockHeader(
            version=1,
            prev_block_hash=GENESIS_PREV_HASH,
            merkle_root=b"\x00" * 32,  # computed below
            timestamp=GENESIS_TIMESTAMP,
            bits=GENESIS_BITS,
            nonce=0,  # genesis nonce (would be mined in production)
            height=0,
            stake_hash=b"\x00" * 32,
            consensus_flags=ConsensusMode.PURE_POW,
        )

        genesis = cls(
            header=genesis_header,
            transactions=[genesis_coinbase],
        )
        genesis.update_merkle_root()
        return genesis

    # ── String Representation ────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"Block(height={self.height}, "
            f"hash={self.block_hash_hex[:16]}..., "
            f"txs={self.tx_count}, "
            f"size={self.size}B)"
        )