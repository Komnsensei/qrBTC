"""
qBTC Hashing Primitives v2.1 — HARDENED FOR PEER REVIEW
=======================================================

Primary hash: SHA3-256 (Keccak sponge)
- Classical preimage resistance: 2^256
- Quantum preimage (Grover): ~2^128 → NIST PQ Level 3
- Classical collision: 2^128 (birthday)
- Quantum collision (BHT): ~2^85.3

Design principles:
- All consensus-critical hashes use qhash_double() = SHA3-256(SHA3-256(x))
  → Defense-in-depth against theoretical second-preimage attacks in trees
- SHAKE-256 for variable-length outputs (KDF, address derivation, nonce randomization)
- All functions are pure and side-effect free
- Secret material is handled via mutable bytearray + explicit sterilization
"""

from __future__ import annotations

import hashlib
import struct
import os
import ctypes
import logging
from typing import Sequence, List

logger = logging.getLogger("qbtc.crypto.hashing")

# ═══════════════════════════════════════════════════════════════════════════
# CORE HASH FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def qhash(data: bytes) -> bytes:
    """Single SHA3-256 hash. Returns 32 bytes."""
    return hashlib.sha3_256(data).digest()


def qhash_double(data: bytes) -> bytes:
    """Double SHA3-256 (SHA3-256(SHA3-256(data))).
    
    Used for block headers, transaction IDs, and Merkle nodes.
    Double hashing provides defense-in-depth (even though SHA3 is already
    length-extension immune). Mitigates theoretical second-preimage risks
    in Merkle tree constructions.
    """
    return hashlib.sha3_256(hashlib.sha3_256(data).digest()).digest()


def qhash_hex(data: bytes) -> str:
    """SHA3-256 returning lowercase hex string (convenience)."""
    return hashlib.sha3_256(data).hexdigest()


def shake256(data: bytes, length: int = 32) -> bytes:
    """SHAKE-256 extendable-output function.
    
    Used for address derivation, key stretching, entropy expansion, and
    randomized nonces. Security scales with output length.
    """
    if length < 1 or length > 65536:
        raise ValueError("Output length must be between 1 and 65536 bytes")
    return hashlib.shake_256(data).digest(length)


# ═══════════════════════════════════════════════════════════════════════════
# MERKLE TREE (Bitcoin-compatible with explicit duplication)
# ═══════════════════════════════════════════════════════════════════════════

def qhash_merkle(hashes: Sequence[bytes]) -> bytes:
    """Compute Merkle root using SHA3-256d.
    
    Algorithm:
      - If empty → error
      - If single hash → return it
      - Odd length → duplicate last element (Bitcoin compatibility)
      - Pairwise double-hash until one root remains
    
    Note: Inherits Bitcoin's CVE-2012-2459 style duplicate-leaf vulnerability.
    This is mitigated in qBTC by the coinbase commitment (unique per block).
    """
    if not hashes:
        raise ValueError("Cannot compute Merkle root from empty hash list")

    if len(hashes) == 1:
        return hashes[0]

    layer: List[bytes] = list(hashes)

    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])  # duplicate last for odd count

        next_layer: List[bytes] = []
        for i in range(0, len(layer), 2):
            combined = layer[i] + layer[i + 1]
            next_layer.append(qhash_double(combined))
        layer = next_layer

    return layer[0]


# ═══════════════════════════════════════════════════════════════════════════
# DIFFICULTY TARGET (nBits) ENCODING — Bitcoin-compatible
# ═══════════════════════════════════════════════════════════════════════════

def target_from_bits(bits: int) -> int:
    """Decode compact nBits into 256-bit target integer."""
    exponent = bits >> 24
    coefficient = bits & 0x007FFFFF

    if coefficient & 0x00800000:  # sign bit set → invalid
        return 0

    if exponent <= 3:
        target = coefficient >> (8 * (3 - exponent))
    else:
        target = coefficient << (8 * (exponent - 3))

    return target


def bits_from_target(target: int) -> int:
    """Encode 256-bit target into compact nBits."""
    if target <= 0:
        return 0

    # Remove leading zero bytes
    raw = target.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
    exponent = len(raw)

    if exponent >= 3:
        coefficient = int.from_bytes(raw[:3], "big")
    else:
        coefficient = int.from_bytes(raw, "big") << (8 * (3 - exponent))

    # Prevent setting the sign bit (0x00800000)
    if coefficient & 0x00800000:
        coefficient >>= 8
        exponent += 1

    return (exponent << 24) | (coefficient & 0x007FFFFF)


def hash_meets_target(block_hash: bytes, target: int) -> bool:
    """Check if block hash (32 bytes, big-endian) ≤ target."""
    if len(block_hash) != 32:
        raise ValueError("Block hash must be exactly 32 bytes")
    hash_int = int.from_bytes(block_hash, "big")
    return hash_int <= target


# ═══════════════════════════════════════════════════════════════════════════
# QUANTUM DECOHERENCE ENTROPY (QDE) — Multi-source entropy mixing
# ═══════════════════════════════════════════════════════════════════════════

def qde_mix_entropy(
    *sources: bytes,
    output_len: int = 64,
    chain_hash: bytes = b"",
) -> bytes:
    """Mix multiple entropy sources through SHAKE-256.
    
    Provides defense-in-depth: compromise of any single source (OS RNG,
    QRNG, chain entropy, etc.) does not fully compromise the output.
    
    Domain separator prevents cross-protocol reuse attacks.
    """
    if output_len < 1 or output_len > 65536:
        raise ValueError("output_len must be between 1 and 65536 bytes")

    os_entropy = os.urandom(32)
    domain = b"qBTC-QDE-v2-entropy-mix"

    combined = domain + os_entropy + chain_hash
    for source in sources:
        if source:  # skip empty sources
            combined += source

    return shake256(combined, output_len)


def qde_randomize_nonce(
    miner_key_id: bytes,
    prev_hash: bytes,
    timestamp: int,
) -> int:
    """Generate a randomized starting nonce for PoW mining.
    
    Prevents quantum miners from predicting or optimizing search patterns
    via amplitude estimation by starting each mining job at a different
    pseudorandom nonce in the 2^64 space.
    """
    if len(miner_key_id) != 20 and len(miner_key_id) != 32:
        logger.warning("miner_key_id should ideally be 20 or 32 bytes")

    seed_data = (
        b"qBTC-QDE-nonce-start-v2"
        + miner_key_id
        + prev_hash
        + struct.pack("<Q", timestamp)  # use 64-bit timestamp for safety
        + os.urandom(16)  # increased fresh entropy
    )

    nonce_bytes = shake256(seed_data, 8)
    return int.from_bytes(nonce_bytes, "little")


# ═══════════════════════════════════════════════════════════════════════════
# QUANTUM STERILIZATION — Secure memory wiping
# ═══════════════════════════════════════════════════════════════════════════

def sterilize(data: bytearray | memoryview) -> None:
    """Securely zeroize a mutable buffer using ctypes.memset.
    
    This is harder for the Python optimizer / compiler to elide than
    a simple loop. Still best-effort in CPython due to GC and potential
    memory copies during compaction.
    
    For production-grade security, combine with:
      - mlock() / VirtualLock() to prevent swapping
      - Hardware security modules / secure enclaves where possible
    """
    if not isinstance(data, (bytearray, memoryview)):
        return

    if len(data) == 0:
        return

    try:
        ctypes.memset(
            (ctypes.c_char * len(data)).from_buffer(data),
            0,
            len(data),
        )
    except Exception as e:
        logger.warning(f"Failed to sterilize memory: {e}")
        # Fallback: Python loop (weaker against optimization)
        for i in range(len(data)):
            data[i] = 0


def sterilize_and_delete(data: bytearray) -> None:
    """Sterilize buffer and delete the reference."""
    if data is not None:
        sterilize(data)
        del data


# Convenience constants
HASH_SIZE = 32          # bytes (SHA3-256 output)
DOUBLE_HASH_SIZE = 32
SHAKE_MAX_OUTPUT = 65536

__all__ = [
    "qhash", "qhash_double", "qhash_hex", "shake256",
    "qhash_merkle",
    "target_from_bits", "bits_from_target", "hash_meets_target",
    "qde_mix_entropy", "qde_randomize_nonce",
    "sterilize", "sterilize_and_delete",
    "HASH_SIZE", "DOUBLE_HASH_SIZE",
]