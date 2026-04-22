"""
qBTC Protocol Constants
========================
All consensus-critical constants for the Quantum Bitcoin protocol.
SHA3 family provides 128-bit post-quantum security at 256-bit output
(Grover halves effective preimage security). All asymmetric crypto uses
NIST FIPS 203/204/205 post-quantum standards.
"""

from __future__ import annotations
from enum import IntEnum, StrEnum
from typing import Final

# ── NETWORK ──────────────────────────────────────────────────────────────────
MAINNET_MAGIC: Final[bytes] = b"\xf9\xbe\xb4\xd9"
TESTNET_MAGIC: Final[bytes] = b"\x0b\x11\x09\x07"
MAINNET_PORT: Final[int] = 19333
TESTNET_PORT: Final[int] = 19444
PROTOCOL_VERSION: Final[int] = 1
USER_AGENT: Final[str] = "/qBTC:0.1.0/"

# ── BLOCK ────────────────────────────────────────────────────────────────────
MAX_BLOCK_SIZE: Final[int] = 4_000_000          # 4 MB
TARGET_BLOCK_TIME: Final[int] = 120              # 2 minutes
DIFFICULTY_ADJUSTMENT_INTERVAL: Final[int] = 1008
MAX_TARGET: Final[int] = (
    0x00000000FFFF0000000000000000000000000000000000000000000000000000
)

# ── MONETARY ─────────────────────────────────────────────────────────────────
COIN: Final[int] = 100_000_000                   # 1 qBTC = 10^8 quantum-sats
MAX_MONEY: Final[int] = 21_000_000 * COIN
INITIAL_BLOCK_REWARD: Final[int] = 50 * COIN
HALVING_INTERVAL: Final[int] = 210_000
COINBASE_MATURITY: Final[int] = 100

# ── TRANSACTION ──────────────────────────────────────────────────────────────
MAX_TX_SIZE: Final[int] = 1_000_000
DUST_THRESHOLD: Final[int] = 546
MIN_TX_FEE_RATE: Final[int] = 1                  # sat/byte

# ── CRYPTOGRAPHY ─────────────────────────────────────────────────────────────
class SigScheme(StrEnum):
    ML_DSA_44  = "ML-DSA-44"
    ML_DSA_65  = "ML-DSA-65"
    ML_DSA_87  = "ML-DSA-87"
    SLH_DSA_SHA2_128f  = "SLH-DSA-SHA2-128f"
    SLH_DSA_SHA2_256f  = "SLH-DSA-SHA2-256f"
    SLH_DSA_SHAKE_256f = "SLH-DSA-SHAKE-256f"

class KEMScheme(StrEnum):
    ML_KEM_512  = "ML-KEM-512"
    ML_KEM_768  = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"

DEFAULT_SIG_SCHEME: Final[str]  = SigScheme.ML_DSA_65
FALLBACK_SIG_SCHEME: Final[str] = SigScheme.SLH_DSA_SHA2_256f
DEFAULT_KEM_SCHEME: Final[str]  = KEMScheme.ML_KEM_1024

# ── CONSENSUS (Hybrid QPoW + PoS) ───────────────────────────────────────────
class ConsensusMode(IntEnum):
    PURE_POW = 0       # Genesis phase: blocks 0 → 10 000
    HYBRID   = 1       # Main phase:   PoW 60 % + PoS 40 %
    PURE_POS = 2       # Future governance-activated

HYBRID_ACTIVATION_HEIGHT: Final[int] = 10_000
MIN_STAKE_AMOUNT: Final[int] = 100 * COIN
MIN_STAKE_AGE: Final[int] = 1008          # blocks
POW_WEIGHT: Final[float] = 0.6
POS_WEIGHT: Final[float] = 0.4

# ── ADDRESSES ────────────────────────────────────────────────────────────────
QBTC_HRP: Final[str] = "qbtc"
TESTNET_HRP: Final[str] = "tqbtc"

# ── GENESIS ──────────────────────────────────────────────────────────────────
GENESIS_PREV_HASH: Final[bytes] = b"\x00" * 32
GENESIS_TIMESTAMP: Final[int] = 1745024400
GENESIS_BITS: Final[int] = 0x1d00ffff
GENESIS_COINBASE_MSG: Final[str] = (
    "qBTC/2025-04-19/Post-Quantum Dawn: The SHA3 chain begins"
)

# ── P2P ──────────────────────────────────────────────────────────────────────
MAX_PEERS: Final[int] = 125
MAX_OUTBOUND: Final[int] = 8
HANDSHAKE_TIMEOUT: Final[int] = 30
PING_INTERVAL: Final[int] = 120
MAX_MESSAGE_SIZE: Final[int] = 32_000_000

# ── MEMPOOL ──────────────────────────────────────────────────────────────────
MAX_MEMPOOL_SIZE: Final[int] = 300_000_000   # 300 MB
MEMPOOL_EXPIRY: Final[int] = 336 * 3600      # 14 days