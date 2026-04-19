"""
qBTC P2P Protocol v2 — HARDENED FOR PEER REVIEW
==================================================
Message Types, Framing, and Peer Model.

Wire Format (each message):
    [4B: magic] [1B: msg_type] [4B: payload_len] [payload] [4B: checksum]
    checksum = SHA3-256(payload)[:4]

This provides message integrity via SHA3-256 truncated hash.
The 4-byte checksum gives 2^32 collision resistance, which is
sufficient for transport-layer integrity (not security-critical).
"""
from __future__ import annotations
import asyncio
import struct
import time
import os
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Optional, Tuple
from qbtc.core.constants import MAX_MESSAGE_SIZE
from qbtc.crypto.hashing import qhash


# ═══════════════════════════════════════════════════════════════════════════
# MESSAGE TYPES
# ═══════════════════════════════════════════════════════════════════════════

class MsgType(IntEnum):
    """P2P message type identifiers."""
    VERSION   = 0x01
    VERACK    = 0x02
    PING      = 0x03
    PONG      = 0x04
    GETBLOCKS = 0x10
    INV       = 0x11
    GETDATA   = 0x12
    BLOCK     = 0x13
    TX        = 0x14
    GETPEERS  = 0x20
    PEERS     = 0x21
    REJECT    = 0xFF


class InvType(IntEnum):
    """Inventory item type identifiers."""
    TX    = 1
    BLOCK = 2


# ═══════════════════════════════════════════════════════════════════════════
# PEER MODEL
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Peer:
    """Represents a connected P2P peer.

    Tracks handshake state, protocol version, latency, and
    connection metadata for peer management.
    """
    host: str
    port: int
    reader: Optional[asyncio.StreamReader] = field(default=None, repr=False)
    writer: Optional[asyncio.StreamWriter] = field(default=None, repr=False)
    version_sent: bool = False
    version_received: bool = False
    verack_sent: bool = False
    verack_received: bool = False
    protocol_version: int = 0
    user_agent: str = ""
    best_height: int = 0
    connected_at: float = 0.0
    last_seen: float = 0.0
    last_ping: float = 0.0
    latency_ms: float = 0.0
    is_inbound: bool = False
    is_connected: bool = False
    shared_secret: Optional[bytes] = field(default=None, repr=False)

    @property
    def addr(self) -> str:
        """Peer address as host:port string."""
        return f"{self.host}:{self.port}"

    @property
    def is_handshaked(self) -> bool:
        """True if the full handshake is complete."""
        return (
            self.version_sent
            and self.version_received
            and self.verack_sent
            and self.verack_received
        )

    def __repr__(self) -> str:
        status = "handshaked" if self.is_handshaked else "connecting"
        direction = "inbound" if self.is_inbound else "outbound"
        return f"Peer({self.addr}, {direction}, {status}, h={self.best_height})"


# ═══════════════════════════════════════════════════════════════════════════
# MESSAGE ENCODING / DECODING
# ═══════════════════════════════════════════════════════════════════════════

def encode_message(magic: bytes, msg_type: MsgType, payload: bytes) -> bytes:
    """Encode a P2P message with magic, type, length, payload, and checksum.

    Format: [4B magic] [1B type] [4B payload_len] [payload] [4B checksum]
    Checksum: SHA3-256(payload)[:4]
    """
    checksum = qhash(payload)[:4]
    return (
        magic
        + struct.pack("!B", msg_type)
        + struct.pack("!I", len(payload))
        + payload
        + checksum
    )


async def read_message(
    reader: asyncio.StreamReader, magic: bytes
) -> Tuple[MsgType, bytes]:
    """Read and validate a P2P message from a stream.

    Validates: magic bytes, message size limit, and SHA3-256 checksum.

    Returns:
        (msg_type, payload) tuple.

    Raises:
        ValueError: if magic is wrong, message too large, or checksum fails.
    """
    # Read header: 4B magic + 1B type + 4B length = 9 bytes
    header = await asyncio.wait_for(reader.readexactly(9), timeout=30)
    if header[:4] != magic:
        raise ValueError(f"Bad magic: {header[:4].hex()}")

    msg_type = MsgType(header[4])
    payload_len = struct.unpack("!I", header[5:9])[0]

    if payload_len > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {payload_len}")

    # Read payload + 4B checksum
    data = await asyncio.wait_for(
        reader.readexactly(payload_len + 4), timeout=60
    )
    payload = data[:payload_len]
    checksum = data[payload_len:]

    if checksum != qhash(payload)[:4]:
        raise ValueError("Checksum mismatch")

    return msg_type, payload


# ═══════════════════════════════════════════════════════════════════════════
# VERSION MESSAGE
# ═══════════════════════════════════════════════════════════════════════════

def encode_version_payload(
    protocol_version: int,
    best_height: int,
    user_agent: str,
    listen_port: int,
) -> bytes:
    """Encode a VERSION message payload.

    Format:
        [4B: protocol_version] [4B: best_height] [2B: listen_port]
        [2B: user_agent_len] [user_agent] [8B: timestamp]
    """
    ua = user_agent.encode()[:256]
    return (
        struct.pack("!IIH", protocol_version, best_height, listen_port)
        + struct.pack("!H", len(ua))
        + ua
        + struct.pack("!Q", int(time.time()))
    )


def decode_version_payload(data: bytes) -> dict:
    """Decode a VERSION message payload.

    Returns:
        Dict with keys: protocol_version, best_height, listen_port,
        user_agent, timestamp.
    """
    v, h, p = struct.unpack("!IIH", data[:10])
    ul = struct.unpack("!H", data[10:12])[0]
    ua = data[12:12 + ul].decode("utf-8", errors="replace")
    ts = struct.unpack("!Q", data[12 + ul:20 + ul])[0]
    return {
        "protocol_version": v,
        "best_height": h,
        "listen_port": p,
        "user_agent": ua,
        "timestamp": ts,
    }