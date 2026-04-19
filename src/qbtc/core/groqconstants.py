"""
qBTC Protocol Constants v2.1 — HARDENED FOR PEER REVIEW
=======================================================

All numeric values are either:
- Directly from NIST FIPS 203/204/205 (Aug 2024 final)
- Derived from first-principles cryptographic analysis (Grover, BHT)
- Compatible with Bitcoin where sensible for ecosystem transition

Post-quantum security floor: NIST Level 3 (ML-DSA-65 + ML-KEM-1024)
Hash security: SHA3-256 → 128-bit quantum preimage resistance (Grover)
"""

from __future__ import annotations

from enum import IntEnum, StrEnum
from typing import Final
from dataclasses import dataclass

# ═══════════════════════════════════════════════════════════════════════════
# NETWORK IDENTIFICATION
# ═══════════════════════════════════════════════════════════════════════════

MAINNET_MAGIC: Final[bytes] = b"\xf9\xbe\xb4\xd9"
TESTNET_MAGIC: Final[bytes] = b"\x0b\x11\x09\x07"

MAINNET_PORT: Final[int] = 19333
TESTNET_PORT: Final[int] = 19444

PROTOCOL_VERSION: Final[int] = 1
USER_AGENT: Final[str] = "/qBTC:0.2.1-hardened/"

# ═══════════════════════════════════════════════════════════════════════════
# BLOCK PARAMETERS
# ═══════════════════════════════════════════════════════════════════════════

MAX_BLOCK_SIZE: Final[int] = 4_000_000          # 4 MB base (accommodates PQ signature bloat)
MAX_BLOCK_WEIGHT: Final[int] = 16_000_000       # 16M weight units (with sig discount)

TARGET_BLOCK_TIME: Final[int] = 120             # 2 minutes per block
DIFFICULTY_ADJUSTMENT_INTERVAL: Final[int] = 1008  # ~1.4 days (1008 blocks)

MAX_TARGET: Final[int] = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
BLOCK_HEADER_SIZE: Final[int] = 122             # bytes (fixed layout)

# Validation
assert MAX_BLOCK_SIZE > 1_000_000, "Block size must be larger than Bitcoin legacy"
assert MAX_BLOCK_WEIGHT % 4_000_000 == 0, "Weight should be multiple of base size for clean scaling"

# ═══════════════════════════════════════════════════════════════════════════
# MONETARY POLICY (Bitcoin-compatible)
# ═══════════════════════════════════════════════════════════════════════════

COIN: Final[int] = 100_000_000                  # 1 qBTC = 10^8 quantum-sats
MAX_MONEY: Final[int] = 21_000_000 * COIN       # 21 million qBTC hard cap

INITIAL_BLOCK_REWARD: Final[int] = 50 * COIN
HALVING_INTERVAL: Final[int] = 210_000          # blocks (~8.4 months at 2min/block)
COINBASE_MATURITY: Final[int] = 100             # blocks before coinbase can be spent

# ═══════════════════════════════════════════════════════════════════════════
# TRANSACTION PARAMETERS
# ═══════════════════════════════════════════════════════════════════════════

MAX_TX_SIZE: Final[int] = 1_000_000             # 1 MB per transaction
DUST_THRESHOLD: Final[int] = 546                # quantum-sats (same as Bitcoin)
MIN_TX_FEE_RATE: Final[int] = 1                 # sat/byte

# Signature weight discount (75% discount → 25% weight)
# Rationale: PQ signatures are large (~3309 bytes) but verification is fast.
# This prevents signature bloat from dominating block capacity.
SIG_WEIGHT_DISCOUNT: Final[float] = 0.25        # sig byte contributes only 0.25 weight

# ═══════════════════════════════════════════════════════════════════════════
# POST-QUANTUM SIGNATURE SCHEMES (NIST FIPS 204 & 205)
# ═══════════════════════════════════════════════════════════════════════════

class SigScheme(StrEnum):
    ML_DSA_44 = "ML-DSA-44"          # NIST Level 2
    ML_DSA_65 = "ML-DSA-65"          # NIST Level 3 — RECOMMENDED DEFAULT
    ML_DSA_87 = "ML-DSA-87"          # NIST Level 5
    SLH_DSA_SHA2_128F = "SLH-DSA-SHA2-128f"   # NIST Level 1 (fast, smaller sigs)
    SLH_DSA_SHA2_256F = "SLH-DSA-SHA2-256f"   # NIST Level 5 — STRONG FALLBACK
    SLH_DSA_SHAKE_256F = "SLH-DSA-SHAKE-256f" # NIST Level 5


@dataclass(frozen=True)
class SigParams:
    """Exact parameters from NIST FIPS 204/205 (final, Aug 2024)."""
    scheme: str
    nist_level: int
    pk_bytes: int
    sk_bytes: int
    sig_bytes: int
    security_model: str      # SUF-CMA or EUF-CMA
    assumption: str          # hardness assumption


# ML-DSA (Module-Lattice, FIPS 204) — Module-LWE + Module-SIS
ML_DSA_44_PARAMS = SigParams("ML-DSA-44", 2, 1312, 2560, 2420, "SUF-CMA", "Module-LWE + Module-SIS")
ML_DSA_65_PARAMS = SigParams("ML-DSA-65", 3, 1952, 4032, 3309, "SUF-CMA", "Module-LWE + Module-SIS")
ML_DSA_87_PARAMS = SigParams("ML-DSA-87", 5, 2592, 4896, 4627, "SUF-CMA", "Module-LWE + Module-SIS")

# SLH-DSA (Stateless Hash-Based, FIPS 205) — Pure hash security (no algebraic assumptions)
SLH_DSA_SHA2_128F_PARAMS = SigParams("SLH-DSA-SHA2-128f", 1, 32, 64, 17088, "EUF-CMA", "Hash preimage resistance")
SLH_DSA_SHA2_256F_PARAMS = SigParams("SLH-DSA-SHA2-256f", 5, 64, 128, 49856, "EUF-CMA", "Hash preimage resistance")
SLH_DSA_SHAKE_256F_PARAMS = SigParams("SLH-DSA-SHAKE-256f", 5, 64, 128, 49856, "EUF-CMA", "Hash preimage resistance")


SIG_PARAMS: dict[str, SigParams] = {
    "ML-DSA-44": ML_DSA_44_PARAMS,
    "ML-DSA-65": ML_DSA_65_PARAMS,
    "ML-DSA-87": ML_DSA_87_PARAMS,
    "SLH-DSA-SHA2-128f": SLH_DSA_SHA2_128F_PARAMS,
    "SLH-DSA-SHA2-256f": SLH_DSA_SHA2_256F_PARAMS,
    "SLH-DSA-SHAKE-256f": SLH_DSA_SHAKE_256F_PARAMS,
}

DEFAULT_SIG_SCHEME: Final[str] = SigScheme.ML_DSA_65
FALLBACK_SIG_SCHEME: Final[str] = SigScheme.SLH_DSA_SHA2_256F

# ═══════════════════════════════════════════════════════════════════════════
# POST-QUANTUM KEY ENCAPSULATION (NIST FIPS 203)
# ═══════════════════════════════════════════════════════════════════════════

class KEMScheme(StrEnum):
    ML_KEM_512 = "ML-KEM-512"   # Level 1
    ML_KEM_768 = "ML-KEM-768"   # Level 3
    ML_KEM_1024 = "ML-KEM-1024" # Level 5 — RECOMMENDED


@dataclass(frozen=True)
class KEMParams:
    """Exact parameters from NIST FIPS 203 (final)."""
    scheme: str
    nist_level: int
    ek_bytes: int      # encapsulation key (public)
    dk_bytes: int      # decapsulation key (private)
    ct_bytes: int      # ciphertext
    ss_bytes: int      # shared secret


ML_KEM_512_PARAMS = KEMParams("ML-KEM-512", 1, 800, 1632, 768, 32)
ML_KEM_768_PARAMS = KEMParams("ML-KEM-768", 3, 1184, 2400, 1088, 32)
ML_KEM_1024_PARAMS = KEMParams("ML-KEM-1024", 5, 1568, 3168, 1568, 32)


KEM_PARAMS: dict[str, KEMParams] = {
    "ML-KEM-512": ML_KEM_512_PARAMS,
    "ML-KEM-768": ML_KEM_768_PARAMS,
    "ML-KEM-1024": ML_KEM_1024_PARAMS,
}

DEFAULT_KEM_SCHEME: Final[str] = KEMScheme.ML_KEM_1024

# ═══════════════════════════════════════════════════════════════════════════
# HASHING & QUANTUM SECURITY
# ═══════════════════════════════════════════════════════════════════════════

HASH_ALGO: Final[str] = "sha3_256"
HASH_OUTPUT_BYTES: Final[int] = 32
HASH_OUTPUT_BITS: Final[int] = 256

# Quantum security (Grover attack)
HASH_PQ_PREIMAGE_BITS: Final[int] = 128        # ceil(256/2)
HASH_PQ_COLLISION_BITS: Final[float] = 85.3     # Brassard-Hoyer-Tapp ~256/3

# ═══════════════════════════════════════════════════════════════════════════
# QUANTUM DECOHERENCE ENTROPY (QDE) FRAMEWORK
# ═══════════════════════════════════════════════════════════════════════════

class EntropySource(IntEnum):
    OS_CSPRNG = 0      # os.urandom — always present
    QRNG_HARDWARE = 1  # Optional quantum hardware RNG (SP 800-90B)
    CHAIN_ENTROPY = 2  # Previous block hash binding


ENTROPY_MIX_OUTPUT_BYTES: Final[int] = 64
STERILIZE_ON_USE: Final[bool] = True

# ═══════════════════════════════════════════════════════════════════════════
# CONSENSUS — THREE-PHASE TRANSITION
# ═══════════════════════════════════════════════════════════════════════════

class ConsensusMode(IntEnum):
    PURE_POW = 0
    HYBRID_POW_POS = 1
    PURE_POS = 2


HYBRID_ACTIVATION_HEIGHT: Final[int] = 10_000
POS_ACTIVATION_HEIGHT: Final[int] = 1_000_000   # Can be lowered via governance

# PoS parameters
MIN_STAKE_AMOUNT: Final[int] = 100 * COIN
MIN_STAKE_AGE: Final[int] = 1008                # ~1.4 days
MAX_STAKE_AGE: Final[int] = 64_800              # ~90 days

# Hybrid weighting (PoW remains dominant for security)
POW_WEIGHT: Final[float] = 0.60
POS_WEIGHT: Final[float] = 0.40
assert abs(POW_WEIGHT + POS_WEIGHT - 1.0) < 1e-9

# ═══════════════════════════════════════════════════════════════════════════
# PROOF-OF-WORK & GROVER RESISTANCE
# ═══════════════════════════════════════════════════════════════════════════

NONCE_BITS: Final[int] = 64
GROVER_EFFECTIVE_BITS: Final[int] = NONCE_BITS // 2   # 32 bits — matches classical Bitcoin difficulty

# ═══════════════════════════════════════════════════════════════════════════
# ADDRESSES (Bech32m)
# ═══════════════════════════════════════════════════════════════════════════

QBTC_HRP: Final[str] = "qbtc"
TESTNET_HRP: Final[str] = "tqbtc"

ADDRESS_WITNESS_VERSION: Final[int] = 1
ADDRESS_PROGRAM_LEN: Final[int] = 32   # SHAKE-256 output

# ═══════════════════════════════════════════════════════════════════════════
# GENESIS BLOCK
# ═══════════════════════════════════════════════════════════════════════════

GENESIS_PREV_HASH: Final[bytes] = b"\x00" * 32
GENESIS_TIMESTAMP: Final[int] = 1745024400          # 2025-04-19 00:00:00 UTC
GENESIS_BITS: Final[int] = 0x1d00ffff
GENESIS_COINBASE_MSG: Final[str] = "qBTC/2025-04-19/Post-Quantum Dawn: The SHA3 chain begins"

# ═══════════════════════════════════════════════════════════════════════════
# P2P NETWORK & MEMPOOL
# ═══════════════════════════════════════════════════════════════════════════

MAX_PEERS: Final[int] = 125
MAX_OUTBOUND: Final[int] = 8

HANDSHAKE_TIMEOUT: Final[int] = 30      # seconds
PING_INTERVAL: Final[int] = 120         # seconds

MAX_MESSAGE_SIZE: Final[int] = 32_000_000   # 32 MB
MAX_MEMPOOL_SIZE: Final[int] = 300_000_000  # 300 MB
MEMPOOL_EXPIRY: Final[int] = 336 * 3600     # 14 days

# ═══════════════════════════════════════════════════════════════════════════
# CAPACITY ESTIMATES (for planning)
# ═══════════════════════════════════════════════════════════════════════════

# Approximate transaction sizes with ML-DSA-65
EST_TX_SIZE_1IN_2OUT: Final[int] ≈ 1952 + 3309 + 2*29 + 12   # ~5.3 KB
EST_TX_SIZE_2IN_2OUT: Final[int] ≈ 2*(1952 + 3309) + 2*29 + 12  # ~10.6 KB

EST_TXS_PER_BLOCK: Final[int] = MAX_BLOCK_SIZE // EST_TX_SIZE_1IN_2OUT   # ~750 txs/block

# Final sanity checks
assert INITIAL_BLOCK_REWARD <= MAX_MONEY
assert HALVING_INTERVAL > 0
assert SIG_WEIGHT_DISCOUNT > 0 and SIG_WEIGHT_DISCOUNT < 1.0