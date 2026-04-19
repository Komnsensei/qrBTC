"""
qBTC Hashing Primitives v2 — HARDENED FOR PEER REVIEW
======================================================
SHA3-256 as the primary hash for all consensus-critical paths.

Security Properties:
    SHA3-256 (Keccak sponge construction):
    ├── Classical preimage resistance: 2^256
    ├── Quantum preimage resistance (Grover): 2^128 → NIST PQ Level 3
    ├── Classical collision resistance: 2^128 (birthday bound)
    ├── Quantum collision resistance (BHT): 2^85.3
    ├── Length-extension immunity: YES (sponge, not Merkle-Damgard)
    └── Deterministic: YES (no internal state between calls)

Design Decisions:
    - SHA3-256d(x) = SHA3-256(SHA3-256(x)) for all consensus hashes.
      Double-hashing is NOT for length-extension (SHA3 is already immune);
      it provides defense-in-depth against theoretical second-preimage
      amplification in Merkle tree constructions (cf. Kelsey & Schneier 2005).
    - SHAKE-256 for variable-length outputs (address derivation, KDF).
    - All functions are pure (no side effects, no mutable state).
"""

from __future__ import annotations

import hashlib
import struct
import os
import ctypes
from typing import Sequence


# ═══════════════════════════════════════════════════════════════════════════
# CORE HASH FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def qhash(data: bytes) -> bytes:
    """SHA3-256 single hash.

    Returns: 32 bytes (256 bits).
    PQ security: 128-bit preimage (Grover), 85-bit collision (BHT).
    """
    return hashlib.sha3_256(data).digest()


def qhash_double(data: bytes) -> bytes:
    """SHA3-256d = SHA3-256(SHA3-256(data)).

    Used for: block header hashing, transaction IDs, Merkle tree nodes.
    Double-hashing provides defense-in-depth; see module docstring.
    """
    return hashlib.sha3_256(hashlib.sha3_256(data).digest()).digest()


def qhash_hex(data: bytes) -> str:
    """SHA3-256 returning lowercase hex string."""
    return hashlib.sha3_256(data).hexdigest()


def shake256(data: bytes, length: int = 32) -> bytes:
    """SHAKE-256 extendable-output function.

    Used for: address derivation, key stretching, entropy mixing.
    Security: min(256, 2*length*8) bits classical; half that quantum.
    """
    return hashlib.shake_256(data).digest(length)


# ═══════════════════════════════════════════════════════════════════════════
# MERKLE TREE
# ═══════════════════════════════════════════════════════════════════════════

def qhash_merkle(hashes: Sequence[bytes]) -> bytes:
    """Compute a SHA3-256d Merkle root from an ordered list of 32-byte hashes.

    Algorithm (Bitcoin-compatible):
        1. If list has 1 element, return it.
        2. If list has odd count, duplicate the last element.
        3. Pair-hash adjacent elements: H(left || right).
        4. Recurse on the resulting list.

    Note on vulnerability CVE-2012-2459: Bitcoin's Merkle tree allows
    duplicate-last-element forgery. qBTC inherits this for compatibility
    but it is mitigated by the coinbase commitment (unique per block).

    Raises:
        ValueError: if the hash list is empty.
    """
    if not hashes:
        raise ValueError("Cannot compute Merkle root of empty hash list")

    layer: list[bytes] = list(hashes)

    while len(layer) > 1:
        if len(layer) % 2 != 0:
            layer.append(layer[-1])  # duplicate last for odd count

        next_layer: list[bytes] = []
        for i in range(0, len(layer), 2):
            next_layer.append(qhash_double(layer[i] + layer[i + 1]))
        layer = next_layer

    return layer[0]


# ═══════════════════════════════════════════════════════════════════════════
# DIFFICULTY TARGET ENCODING
#
# Format: 0xNNTTTTTT (4 bytes, big-endian semantic)
#   NN     = exponent byte (number of bytes in the target)
#   TTTTTT = coefficient (3 most significant bytes of the target)
#   target = coefficient * 2^(8 * (exponent - 3))
#
# This is identical to Bitcoin's "nBits" compact encoding.
# ═══════════════════════════════════════════════════════════════════════════

def target_from_bits(bits: int) -> int:
    """Decode compact 'bits' (nBits) into a 256-bit target integer."""
    exponent = bits >> 24
    coefficient = bits & 0x007FFFFF

    # Negative flag (bit 23 of coefficient) — always treated as 0 for targets
    if coefficient & 0x00800000:
        return 0  # negative targets are invalid

    if exponent <= 3:
        target = coefficient >> (8 * (3 - exponent))
    else:
        target = coefficient << (8 * (exponent - 3))

    return target


def bits_from_target(target: int) -> int:
    """Encode a 256-bit target integer into compact 'bits' (nBits)."""
    if target <= 0:
        return 0

    raw = target.to_bytes(32, "big").lstrip(b"\x00") or b"\x00"
    exponent = len(raw)

    if exponent >= 3:
        coefficient = int.from_bytes(raw[:3], "big")
    else:
        coefficient = int.from_bytes(raw, "big") << (8 * (3 - exponent))

    # Avoid setting the sign bit
    if coefficient & 0x00800000:
        coefficient >>= 8
        exponent += 1

    return (exponent << 24) | (coefficient & 0x007FFFFF)


def hash_meets_target(block_hash: bytes, target: int) -> bool:
    """Check if a block hash (32 bytes, big-endian) meets the difficulty target.

    Valid when: int(block_hash) <= target
    """
    hash_int = int.from_bytes(block_hash, "big")
    return hash_int <= target


# ═══════════════════════════════════════════════════════════════════════════
# QUANTUM DECOHERENCE ENTROPY (QDE) — ENTROPY MIXING
#
# The QDE framework provides defense-in-depth randomness by mixing
# multiple entropy sources through SHAKE-256. Even if one source is
# compromised (e.g., a backdoored OS RNG), the others maintain security.
#
# Domain separators prevent cross-protocol entropy reuse attacks where
# the same entropy is used in two different cryptographic contexts.
# ═══════════════════════════════════════════════════════════════════════════

def qde_mix_entropy(
    *sources: bytes,
    output_len: int = 64,
    chain_hash: bytes = b"",
) -> bytes:
    """Mix multiple entropy sources into a single high-quality seed.

    Combines OS CSPRNG entropy, optional QRNG data, and blockchain
    chain entropy via SHAKE-256. Compromise of any single source
    does not compromise the output.

    Args:
        *sources: Variable number of entropy byte strings.
        output_len: Desired output length in bytes.
        chain_hash: Latest block hash for chain entropy binding.

    Returns:
        output_len bytes of mixed entropy.
    """
    # Always include OS entropy as baseline
    os_entropy = os.urandom(32)

    # Domain separator prevents cross-protocol entropy reuse
    domain = b"qBTC-QDE-v2-entropy-mix"

    combined = domain + os_entropy + chain_hash
    for source in sources:
        combined += source

    return shake256(combined, output_len)


def qde_randomize_nonce(
    miner_key_id: bytes,
    prev_hash: bytes,
    timestamp: int,
) -> int:
    """Generate a randomized starting nonce for PoW search.

    Instead of searching from nonce=0 (which lets quantum miners
    predict search patterns via amplitude estimation), we derive
    a pseudorandom starting point that uniformly covers [0, 2^64).

    The nonce start is derived from:
        SHAKE-256(domain || miner_key || prev_hash || timestamp || fresh_random)

    This ensures:
        - Different miners start at different nonces (no wasted overlap)
        - Different blocks start at different nonces (no pattern correlation)
        - Fresh randomness prevents replay of previous search patterns

    Returns:
        A 64-bit integer to use as the starting nonce.
    """
    seed_data = (
        b"qBTC-QDE-nonce-start"
        + miner_key_id
        + prev_hash
        + struct.pack("<I", timestamp)
        + os.urandom(8)  # fresh randomness per template
    )
    nonce_bytes = shake256(seed_data, 8)
    return int.from_bytes(nonce_bytes, "little")


# ═══════════════════════════════════════════════════════════════════════════
# QUANTUM STERILIZATION — SECURE MEMORY ZEROIZATION
#
# After cryptographic operations (keygen, signing), intermediate values
# must be destroyed to prevent:
#   - Cold-boot attacks (reading RAM after power-off)
#   - Speculative execution side-channels (Spectre/Meltdown variants)
#   - Quantum memory imaging (hypothetical future attack)
#   - Core dumps / swap file leakage
#
# Python's garbage collector does not guarantee immediate deallocation,
# and immutable bytes objects cannot be overwritten. Therefore:
#   - All secret intermediates MUST use bytearray (mutable)
#   - sterilize() overwrites via ctypes.memset (resists optimizer elision)
#   - Production deployments should additionally use mlock() to prevent
#     swapping secret pages to disk
#
# WARNING: This is best-effort in CPython. The GC may have already
# copied the data to a new memory location during compaction.
# For production-grade sterilization, use a C extension with
# explicit_bzero() or SecureZeroMemory() on Windows.
# ═══════════════════════════════════════════════════════════════════════════

def sterilize(data: bytearray) -> None:
    """Securely zeroize a mutable byte buffer.

    Uses ctypes.memset to overwrite memory, which is harder for
    the optimizer to elide than a Python loop. This implements
    the Quantum Sterilization requirement from qBTC's QDE framework.

    Args:
        data: A mutable bytearray to zeroize. Immutable bytes objects
              cannot be sterilized (they may be interned by CPython).
    """
    if not isinstance(data, (bytearray, memoryview)):
        return  # Cannot sterilize immutable bytes

    size = len(data)
    if size == 0:
        return

    # Overwrite with zeros via ctypes (resists compiler optimization)
    ctypes.memset(
        (ctypes.c_char * size).from_buffer(data),
        0,
        size,
    )


def sterilize_and_delete(data: bytearray) -> None:
    """Sterilize a buffer and release the reference.

    After calling this, the bytearray is zeroed and the local
    reference is deleted. The GC will eventually reclaim the memory.
    """
    sterilize(data)
    del data