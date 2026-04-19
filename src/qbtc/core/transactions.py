"""
qBTC Transaction Model v2 — HARDENED FOR PEER REVIEW
======================================================
Post-quantum transaction structure using ML-DSA-65 signatures.
Each input carries a full quantum-resistant public key and signature
(no ECDSA, no secp256k1 — those are Shor-vulnerable).

Transaction Wire Format:
    +------------------------------------------------------+
    |  version          : uint32     (4 bytes)             |
    |  input_count      : varint                           |
    |  inputs[]         : TxInput[]                        |
    |    +- prev_txid   : 32 bytes                         |
    |    +- prev_index  : uint32                           |
    |    +- sig_scheme  : uint8                            |
    |    +- pubkey_len  : uint16                           |
    |    +- pubkey      : [pubkey_len] bytes               |
    |    +- sig_len     : uint16                           |
    |    +- signature   : [sig_len] bytes                  |
    |    +- sequence    : uint32                           |
    |  output_count     : varint                           |
    |  outputs[]        : TxOutput[]                       |
    |    +- amount      : int64      (satoshis)            |
    |    +- pk_hash_len : uint8                            |
    |    +- pk_hash     : [pk_hash_len] bytes              |
    |  locktime         : uint32                           |
    +------------------------------------------------------+

Size Analysis (ML-DSA-65, 1 input / 2 outputs):
    Header:       4 bytes (version) + 1 (in count) + 1 (out count) + 4 (locktime) = 10
    Input:        32 (txid) + 4 (index) + 1 (scheme) + 2 (pk_len) + 1952 (pk)
                  + 2 (sig_len) + 3309 (sig) + 4 (seq) = 5,306 bytes
    Output (x2):  8 (amount) + 1 (hash_len) + 20 (pk_hash) = 29 bytes each = 58
    Total:        ~5,374 bytes (vs Bitcoin's ~225 bytes = ~24x larger)

    The signature weight discount (0.25x) in block weight calculation
    mitigates the impact on block capacity. See constants.py.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Optional, List

from qbtc.crypto.hashing import qhash, qhash_double
from qbtc.crypto.keys import QuantumKeyPair


# ═══════════════════════════════════════════════════════════════════════════
# VARINT ENCODING (Bitcoin-compatible)
#
# Values < 0xFD:        1 byte
# Values <= 0xFFFF:     0xFD + 2 bytes (little-endian)
# Values <= 0xFFFFFFFF: 0xFE + 4 bytes (little-endian)
# Values > 0xFFFFFFFF:  0xFF + 8 bytes (little-endian)
# ═══════════════════════════════════════════════════════════════════════════

def encode_varint(n: int) -> bytes:
    """Encode an integer as a Bitcoin-compatible variable-length integer."""
    if n < 0xFD:
        return struct.pack("<B", n)
    elif n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a varint from data at the given offset.

    Returns:
        (value, new_offset) tuple.
    """
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    elif first == 0xFD:
        return struct.unpack("<H", data[offset + 1:offset + 3])[0], offset + 3
    elif first == 0xFE:
        return struct.unpack("<I", data[offset + 1:offset + 5])[0], offset + 5
    else:
        return struct.unpack("<Q", data[offset + 1:offset + 9])[0], offset + 9


# ═══════════════════════════════════════════════════════════════════════════
# TRANSACTION INPUT
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TxInput:
    """A transaction input spending a previous output.

    Attributes:
        prev_txid:   Hash of the transaction being spent (32 bytes)
        prev_index:  Index of the output in that transaction
        sig_scheme:  Signature scheme ID (0x02 = ML-DSA-65)
        public_key:  Full post-quantum public key of the spender
        signature:   Post-quantum signature over the transaction digest
        sequence:    Sequence number (0xFFFFFFFF = final, lower = RBF)
    """
    prev_txid: bytes          # 32 bytes
    prev_index: int           # uint32
    sig_scheme: int = 0x02    # ML-DSA-65
    public_key: bytes = b""
    signature: bytes = b""
    sequence: int = 0xFFFFFFFF

    # Alias for mempool compatibility
    @property
    def prev_vout(self) -> int:
        return self.prev_index

    @property
    def is_coinbase(self) -> bool:
        """A coinbase input has a null txid and max prev_index."""
        return self.prev_txid == b"\x00" * 32 and self.prev_index == 0xFFFFFFFF

    def serialize(self) -> bytes:
        """Serialize input to wire format."""
        parts = [
            self.prev_txid,                                    # 32 bytes
            struct.pack("<I", self.prev_index),                # 4 bytes
            struct.pack("!B", self.sig_scheme),                # 1 byte
            struct.pack("!H", len(self.public_key)),           # 2 bytes
            self.public_key,
            struct.pack("!H", len(self.signature)),            # 2 bytes
            self.signature,
            struct.pack("<I", self.sequence),                  # 4 bytes
        ]
        return b"".join(parts)

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> tuple["TxInput", int]:
        """Deserialize an input from wire format. Returns (TxInput, new_offset)."""
        prev_txid = data[offset:offset + 32]
        offset += 32
        prev_index = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        sig_scheme = data[offset]
        offset += 1
        pk_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        public_key = data[offset:offset + pk_len]
        offset += pk_len
        sig_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        signature = data[offset:offset + sig_len]
        offset += sig_len
        sequence = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4
        return cls(
            prev_txid=prev_txid,
            prev_index=prev_index,
            sig_scheme=sig_scheme,
            public_key=public_key,
            signature=signature,
            sequence=sequence,
        ), offset

    def serialize_for_signing(self) -> bytes:
        """Serialize input WITHOUT signature for signing digest computation.

        When computing the transaction digest to sign, the signature
        field is excluded (it doesn't exist yet). The public key IS
        included so that the signature commits to the signer's identity.
        """
        parts = [
            self.prev_txid,
            struct.pack("<I", self.prev_index),
            struct.pack("!B", self.sig_scheme),
            struct.pack("!H", len(self.public_key)),
            self.public_key,
            struct.pack("<I", self.sequence),
        ]
        return b"".join(parts)


# ═══════════════════════════════════════════════════════════════════════════
# TRANSACTION OUTPUT
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TxOutput:
    """A transaction output locking funds to a public key hash.

    Attributes:
        amount:        Value in quantum-satoshis (int64)
        pk_hash:       SHA3-256 hash of the recipient's quantum public key
                       (20 bytes for compatibility, or 32 bytes for full hash)
        script_pubkey: Alias for pk_hash (for API compatibility)
    """
    amount: int               # int64, in satoshis
    pk_hash: bytes            # recipient's public key hash

    @property
    def script_pubkey(self) -> bytes:
        """Alias for pk_hash — used by node.py and wallet.py."""
        return self.pk_hash

    def serialize(self) -> bytes:
        """Serialize output to wire format."""
        parts = [
            struct.pack("<q", self.amount),
            struct.pack("!B", len(self.pk_hash)),
            self.pk_hash,
        ]
        return b"".join(parts)

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> tuple["TxOutput", int]:
        """Deserialize an output from wire format."""
        amount = struct.unpack("<q", data[offset:offset + 8])[0]
        offset += 8
        pk_hash_len = data[offset]
        offset += 1
        pk_hash = data[offset:offset + pk_hash_len]
        offset += pk_hash_len
        return cls(amount=amount, pk_hash=pk_hash), offset


# ═══════════════════════════════════════════════════════════════════════════
# TRANSACTION
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Transaction:
    """A qBTC transaction with post-quantum signatures.

    Attributes:
        version:   Protocol version (currently 1)
        inputs:    List of TxInputs
        outputs:   List of TxOutputs
        locktime:  Block height or timestamp lock
        txid:      Cached transaction ID (SHA3-256d of serialized tx)

    Validation Rules (enforced by mempool and consensus):
        1. At least one input and one output
        2. All output amounts >= 0 and <= MAX_MONEY
        3. Total output <= total input (difference = fee)
        4. No duplicate inputs (same txid:vout)
        5. All non-coinbase inputs have valid PQ signatures
        6. Coinbase inputs only in the first tx of a block
        7. Transaction size <= MAX_TX_SIZE
    """
    version: int = 1
    inputs: List[TxInput] = field(default_factory=list)
    outputs: List[TxOutput] = field(default_factory=list)
    locktime: int = 0
    _txid: Optional[bytes] = field(default=None, init=False, repr=False)

    @property
    def txid(self) -> bytes:
        """Transaction ID = SHA3-256d of the full serialized transaction."""
        if self._txid is None:
            self._txid = qhash_double(self.serialize())
        return self._txid

    @property
    def txid_hex(self) -> str:
        """Transaction ID as lowercase hex string."""
        return self.txid.hex()

    @property
    def is_coinbase(self) -> bool:
        """True if this is a coinbase (block reward) transaction."""
        return len(self.inputs) == 1 and self.inputs[0].is_coinbase

    @property
    def total_output(self) -> int:
        """Sum of all output amounts in satoshis."""
        return sum(out.amount for out in self.outputs)

    @property
    def size(self) -> int:
        """Serialized size in bytes."""
        return len(self.serialize())

    @property
    def weight(self) -> int:
        """Transaction weight with signature discount.

        Non-signature bytes count as 4 weight units.
        Signature bytes count as 1 weight unit (0.25x discount).
        This is analogous to SegWit's witness discount.
        """
        sig_bytes = sum(len(inp.signature) for inp in self.inputs)
        non_sig_bytes = self.size - sig_bytes
        return non_sig_bytes * 4 + sig_bytes * 1

    def invalidate_cache(self) -> None:
        """Clear the cached txid (call after modifying the transaction)."""
        self._txid = None

    # ── Serialization ────────────────────────────────────────────────────

    def serialize(self) -> bytes:
        """Full transaction serialization (wire format)."""
        parts = [
            struct.pack("<I", self.version),
            encode_varint(len(self.inputs)),
        ]
        for inp in self.inputs:
            parts.append(inp.serialize())
        parts.append(encode_varint(len(self.outputs)))
        for out in self.outputs:
            parts.append(out.serialize())
        parts.append(struct.pack("<I", self.locktime))
        return b"".join(parts)

    @classmethod
    def deserialize(cls, data: bytes) -> "Transaction":
        """Deserialize a transaction from wire format."""
        offset = 0
        version = struct.unpack("<I", data[offset:offset + 4])[0]
        offset += 4

        in_count, offset = decode_varint(data, offset)
        inputs = []
        for _ in range(in_count):
            inp, offset = TxInput.deserialize(data, offset)
            inputs.append(inp)

        out_count, offset = decode_varint(data, offset)
        outputs = []
        for _ in range(out_count):
            out, offset = TxOutput.deserialize(data, offset)
            outputs.append(out)

        locktime = struct.unpack("<I", data[offset:offset + 4])[0]
        return cls(version=version, inputs=inputs, outputs=outputs, locktime=locktime)

    # ── Signing ──────────────────────────────────────────────────────────

    def signing_digest(self, input_index: int) -> bytes:
        """Compute the SHA3-256d digest to be signed for a specific input.

        This creates a modified serialization where:
        - The target input keeps its public key but has an empty signature
        - All other inputs have empty public keys and signatures
        This prevents signature malleability and ensures each input's
        signature commits to the entire transaction structure.

        Args:
            input_index: Index of the input being signed.

        Returns:
            32-byte SHA3-256d digest.
        """
        parts = [struct.pack("<I", self.version)]
        parts.append(encode_varint(len(self.inputs)))

        for i, inp in enumerate(self.inputs):
            if i == input_index:
                # This input: include PK, exclude signature
                parts.append(inp.serialize_for_signing())
            else:
                # Other inputs: exclude both PK and signature
                parts.append(inp.prev_txid)
                parts.append(struct.pack("<I", inp.prev_index))
                parts.append(struct.pack("!B", inp.sig_scheme))
                parts.append(struct.pack("!H", 0))  # empty PK
                parts.append(struct.pack("<I", inp.sequence))

        parts.append(encode_varint(len(self.outputs)))
        for out in self.outputs:
            parts.append(out.serialize())
        parts.append(struct.pack("<I", self.locktime))

        return qhash_double(b"".join(parts))

    def sign_input(self, input_index: int, keypair: QuantumKeyPair) -> None:
        """Sign a specific input with a quantum key pair.

        Computes the signing digest and produces an ML-DSA-65 signature.
        The public key and signature are stored in the input.

        Args:
            input_index: Index of the input to sign.
            keypair: The QuantumKeyPair with a secret key.

        Raises:
            IndexError: if input_index is out of range.
            ValueError: if the keypair has no secret key.
        """
        if input_index < 0 or input_index >= len(self.inputs):
            raise IndexError(f"Input index {input_index} out of range")

        inp = self.inputs[input_index]
        inp.public_key = keypair.public_key

        # Compute the digest AFTER setting the public key
        digest = self.signing_digest(input_index)

        # Sign with the quantum key pair
        inp.signature = keypair.sign(digest)

        # Invalidate cached txid since we modified the transaction
        self.invalidate_cache()

    def verify_input(self, input_index: int) -> bool:
        """Verify the signature on a specific input.

        Uses the public key stored in the input to verify the signature
        against the computed signing digest.

        Args:
            input_index: Index of the input to verify.

        Returns:
            True if the signature is valid.
        """
        if input_index < 0 or input_index >= len(self.inputs):
            return False

        inp = self.inputs[input_index]
        if inp.is_coinbase:
            return True  # Coinbase inputs have no signature to verify

        if not inp.public_key or not inp.signature:
            return False

        # Reconstruct the signing digest
        digest = self.signing_digest(input_index)

        # Verify using the public key from the input
        from qbtc.crypto.keys import QuantumKeyPair, _ID_SCHEMES
        scheme = _ID_SCHEMES.get(inp.sig_scheme, "ML-DSA-65")
        verifier = QuantumKeyPair.watch_only(scheme, inp.public_key)
        return verifier.verify(digest, inp.signature)

    def verify_all_inputs(self) -> bool:
        """Verify all input signatures.

        Returns:
            True if ALL non-coinbase inputs have valid signatures.
        """
        for i, inp in enumerate(self.inputs):
            if inp.is_coinbase:
                continue
            if not self.verify_input(i):
                return False
        return True

    # ── Coinbase Constructor ─────────────────────────────────────────────

    @classmethod
    def create_coinbase(
        cls,
        height: int,
        reward: int,
        miner_pk_hash: bytes,
        extra_data: bytes = b"",
    ) -> "Transaction":
        """Create a coinbase transaction (block reward).

        Args:
            height: Block height (encoded in the coinbase data).
            reward: Total reward in satoshis (block reward + fees).
            miner_pk_hash: Public key hash of the miner's address.
            extra_data: Optional extra data (e.g., pool name, up to 100 bytes).

        Returns:
            A new coinbase Transaction.
        """
        # Coinbase data: height (4 bytes LE) + extra data
        cb_data = struct.pack("<I", height) + extra_data[:100]

        coinbase_input = TxInput(
            prev_txid=b"\x00" * 32,
            prev_index=0xFFFFFFFF,
            sig_scheme=0x00,         # no signature scheme for coinbase
            public_key=b"",
            signature=cb_data,       # coinbase data goes in signature field
            sequence=0xFFFFFFFF,
        )

        reward_output = TxOutput(
            amount=reward,
            pk_hash=miner_pk_hash,
        )

        return cls(
            version=1,
            inputs=[coinbase_input],
            outputs=[reward_output],
            locktime=0,
        )

    # ── String Representation ────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"Transaction(txid={self.txid_hex[:16]}..., "
            f"inputs={len(self.inputs)}, outputs={len(self.outputs)}, "
            f"size={self.size}B)"
        )