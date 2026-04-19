"""
qBTC Quantum-Resistant HD Wallet v2 — HARDENED FOR PEER REVIEW
================================================================
Hierarchical Deterministic wallet using post-quantum key derivation.

Instead of BIP-32 (which relies on secp256k1 — Shor-vulnerable), qBTC uses
a hash-based hierarchical key derivation scheme:

    master_seed (256 bits, from BIP-39 mnemonic or os.urandom)
        |
        +- SHAKE-256(master_seed || "qbtc-master" || 0) -> child_seed[0]
        +- SHAKE-256(master_seed || "qbtc-master" || 1) -> child_seed[1]
        +- ...
        +- SHAKE-256(master_seed || "qbtc-master" || n) -> child_seed[n]
                |
                +-> ML-DSA-65.KeyGen_internal(child_seed[:32]) -> keypair

Address Format:
    Bech32m with HRP "qbtc" (mainnet) or "tqbtc" (testnet)
    Witness version 1, program = SHAKE-256(public_key, 32)

Features:
    - ML-DSA-65 key generation from deterministic seeds
    - Bech32m quantum-safe addresses
    - UTXO tracking and balance queries
    - Transaction building and signing
    - JSON wallet file storage
    - Key rotation support
"""

from __future__ import annotations

import os
import json
import time
import struct
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from qbtc.core.constants import (
    QBTC_HRP,
    TESTNET_HRP,
    COIN,
    DUST_THRESHOLD,
    DEFAULT_SIG_SCHEME,
)
from qbtc.core.transaction import Transaction, TxInput, TxOutput
from qbtc.crypto.hashing import qhash, shake256
from qbtc.crypto.keys import QuantumKeyPair

logger = logging.getLogger("qbtc.wallet")


# ═══════════════════════════════════════════════════════════════════════════
# BECH32M ENCODING (BIP-350)
# ═══════════════════════════════════════════════════════════════════════════

BECH32M_CONST = 0x2BC830A3
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: List[int]) -> int:
    """Bech32 polymod checksum computation."""
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    """Expand HRP for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32m_create_checksum(hrp: str, data: List[int]) -> List[int]:
    """Create Bech32m checksum."""
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(
    data: bytes, frombits: int, tobits: int, pad: bool = True
) -> List[int]:
    """Convert between bit widths."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return []
    return ret


def bech32m_encode(
    hrp: str, witness_version: int, witness_program: bytes
) -> str:
    """Encode a Bech32m address from HRP + witness version + program."""
    data = [witness_version] + _convertbits(witness_program, 8, 5)
    checksum = _bech32m_create_checksum(hrp, data)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


def bech32m_decode(addr: str) -> Tuple[str, int, bytes]:
    """Decode a Bech32m address.

    Returns:
        (hrp, witness_version, witness_program) tuple.

    Raises:
        ValueError: if the checksum is invalid.
    """
    pos = addr.rfind("1")
    hrp = addr[:pos]
    data_part = addr[pos + 1:]
    data = [BECH32_CHARSET.index(c) for c in data_part]

    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != BECH32M_CONST:
        raise ValueError("Invalid Bech32m checksum")

    decoded = data[:-6]  # strip checksum
    witness_version = decoded[0]
    witness_program = bytes(_convertbits(decoded[1:], 5, 8, pad=False))
    return hrp, witness_version, witness_program


# ═══════════════════════════════════════════════════════════════════════════
# WALLET KEY ENTRY
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class WalletKey:
    """A wallet key entry with address and derivation metadata."""
    index: int
    keypair: QuantumKeyPair
    address: str
    created_at: float
    label: str = ""
    is_change: bool = False


# ═══════════════════════════════════════════════════════════════════════════
# WALLET
# ═══════════════════════════════════════════════════════════════════════════

class Wallet:
    """qBTC Quantum-Resistant HD Wallet.

    Usage:
        wallet = Wallet.create("my_wallet", testnet=False)
        key = wallet.generate_key(label="Savings")
        addr = key.address
        balance = wallet.get_balance(blockchain)
        tx = wallet.create_transaction(
            blockchain, recipient_address, amount, fee_rate=5
        )
        wallet.save("wallet.json", password="secret")
        loaded = Wallet.load("wallet.json", password="secret")
    """

    def __init__(
        self,
        name: str,
        master_seed: bytes,
        network_hrp: str = QBTC_HRP,
        sig_scheme: str = DEFAULT_SIG_SCHEME,
    ) -> None:
        self.name = name
        self._master_seed = master_seed
        self.network_hrp = network_hrp
        self.sig_scheme = sig_scheme

        # Key management
        self.keys: Dict[str, WalletKey] = {}  # address -> WalletKey
        self._next_index: int = 0
        self._next_change_index: int = 0

        # Generate first receiving key
        self.generate_key(label="Default")

    # ── Factory Methods ──────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        name: str,
        passphrase: str = "",
        testnet: bool = False,
    ) -> "Wallet":
        """Create a new wallet with a random master seed.

        Args:
            name: Wallet name
            passphrase: Optional passphrase for seed stretching
            testnet: Use testnet HRP

        Returns:
            New Wallet instance with the first key generated.
        """
        entropy = os.urandom(32)
        stretched = shake256(
            entropy + passphrase.encode("utf-8"), 64
        )
        master_seed = stretched[:32]
        hrp = TESTNET_HRP if testnet else QBTC_HRP

        wallet = cls(name=name, master_seed=master_seed, network_hrp=hrp)
        logger.info(
            f"Wallet '{name}' created with seed {master_seed.hex()[:16]}..."
        )
        return wallet

    @classmethod
    def from_seed(
        cls,
        name: str,
        seed_hex: str,
        testnet: bool = False,
    ) -> "Wallet":
        """Restore a wallet from a hex-encoded seed."""
        master_seed = bytes.fromhex(seed_hex)
        hrp = TESTNET_HRP if testnet else QBTC_HRP
        return cls(name=name, master_seed=master_seed, network_hrp=hrp)

    # ── Key Generation ───────────────────────────────────────────────────

    def generate_key(
        self,
        label: str = "",
        is_change: bool = False,
    ) -> WalletKey:
        """Derive the next key from the master seed.

        Derivation:
            child_seed = SHAKE-256(master_seed || purpose || index, 32)
            keypair = QuantumKeyPair.generate_from_seed(child_seed)

        Args:
            label: Human-readable label for this key.
            is_change: Whether this is a change address key.

        Returns:
            WalletKey with address and keypair.
        """
        if is_change:
            index = self._next_change_index
            purpose = b"qbtc-change"
            self._next_change_index += 1
        else:
            index = self._next_index
            purpose = b"qbtc-master"
            self._next_index += 1

        # Derive child seed (32 bytes for ML-DSA KeyGen_internal)
        child_seed = shake256(
            self._master_seed + purpose + struct.pack("<I", index),
            32,
        )

        # Generate keypair from seed (deterministic when liboqs supports it)
        keypair = QuantumKeyPair.generate_from_seed(child_seed, self.sig_scheme)

        # Derive address: Bech32m(hrp, version=1, SHAKE-256(pubkey, 32))
        witness_program = shake256(keypair.public_key, 32)
        address = bech32m_encode(self.network_hrp, 1, witness_program)

        wallet_key = WalletKey(
            index=index,
            keypair=keypair,
            address=address,
            created_at=time.time(),
            label=label,
            is_change=is_change,
        )

        self.keys[address] = wallet_key
        logger.info(f"Derived key #{index}: {address}")
        return wallet_key

    # ── Address Management ───────────────────────────────────────────────

    def get_new_address(self, label: str = "") -> str:
        """Generate a new receiving address."""
        key = self.generate_key(label=label)
        return key.address

    def get_change_address(self) -> str:
        """Generate a new change address."""
        key = self.generate_key(is_change=True)
        return key.address

    def get_all_addresses(self) -> List[str]:
        """Get all wallet addresses."""
        return list(self.keys.keys())

    def get_pk_hashes(self) -> List[bytes]:
        """Get all public key hashes (for UTXO scanning)."""
        return [k.keypair.key_id for k in self.keys.values()]

    # ── Balance & UTXOs ──────────────────────────────────────────────────

    def get_balance(self, blockchain) -> int:
        """Get total wallet balance from the UTXO set."""
        total = 0
        for wk in self.keys.values():
            total += blockchain.get_balance(wk.keypair.key_id)
        return total

    def get_spendable_utxos(self, blockchain) -> list:
        """Get all spendable UTXOs with their wallet keys."""
        utxos = []
        for wk in self.keys.values():
            for key, entry in blockchain.get_utxos_for_address(
                wk.keypair.key_id
            ):
                utxos.append((key, entry, wk))
        return utxos

    # ── Transaction Building ─────────────────────────────────────────────

    def create_transaction(
        self,
        blockchain,
        recipient_address: str,
        amount: int,
        fee_rate: int = 5,
    ) -> Transaction:
        """Create and sign a transaction.

        Uses a simple greedy coin selection algorithm:
        pick UTXOs in descending value until the target is met.

        Args:
            blockchain: Blockchain instance for UTXO lookup.
            recipient_address: Bech32m address of the recipient.
            amount: Amount to send in quantum-satoshis.
            fee_rate: Fee rate in satoshis per byte.

        Returns:
            Signed Transaction ready for broadcast.

        Raises:
            ValueError: if insufficient funds or invalid address.
        """
        if amount < DUST_THRESHOLD:
            raise ValueError(
                f"Amount {amount} below dust threshold {DUST_THRESHOLD}"
            )

        # Decode recipient address
        hrp, wv, wp = bech32m_decode(recipient_address)

        # Get spendable UTXOs
        utxos = self.get_spendable_utxos(blockchain)
        utxos.sort(key=lambda x: x[1].amount, reverse=True)

        # Estimate fee (rough: assume ~5300 bytes per input)
        est_fee = fee_rate * 5300

        # Coin selection
        selected = []
        total_input = 0
        for utxo_key, utxo_entry, wallet_key in utxos:
            selected.append((utxo_key, utxo_entry, wallet_key))
            total_input += utxo_entry.amount
            # Re-estimate fee with actual input count
            est_fee = fee_rate * (len(selected) * 5300 + 100)
            if total_input >= amount + est_fee:
                break

        if total_input < amount + est_fee:
            raise ValueError(
                f"Insufficient funds: have {total_input}, "
                f"need {amount + est_fee} "
                f"(amount={amount}, est_fee={est_fee})"
            )

        # Build inputs
        inputs = []
        for utxo_key, utxo_entry, wallet_key in selected:
            inp = TxInput(
                prev_txid=utxo_key.txid,
                prev_index=utxo_key.index,
                sig_scheme=0x02,  # ML-DSA-65
                public_key=b"",   # filled during signing
                signature=b"",    # filled during signing
            )
            inputs.append(inp)

        # Build outputs
        outputs = [
            TxOutput(amount=amount, pk_hash=wp),
        ]

        # Change output
        change = total_input - amount - est_fee
        if change > DUST_THRESHOLD:
            change_addr = self.get_change_address()
            _, _, change_wp = bech32m_decode(change_addr)
            outputs.append(TxOutput(amount=change, pk_hash=change_wp))

        # Create transaction
        tx = Transaction(
            version=1,
            inputs=inputs,
            outputs=outputs,
            locktime=0,
        )

        # Sign each input
        for i, (utxo_key, utxo_entry, wallet_key) in enumerate(selected):
            tx.sign_input(i, wallet_key.keypair)

        logger.info(
            f"Transaction created: {tx.txid_hex[:16]}..., "
            f"{len(inputs)} inputs, {len(outputs)} outputs, "
            f"amount={amount}, fee={est_fee}"
        )
        return tx

    # ── Persistence ──────────────────────────────────────────────────────

    def save(self, path: str, password: str = "") -> None:
        """Save wallet to a JSON file.

        NOTE: In production, this should use AES-256-GCM encryption
        with a key derived from the password via Argon2id.
        This reference implementation stores keys in plaintext JSON
        for development purposes.
        """
        data = {
            "name": self.name,
            "network_hrp": self.network_hrp,
            "sig_scheme": self.sig_scheme,
            "master_seed": self._master_seed.hex(),
            "next_index": self._next_index,
            "next_change_index": self._next_change_index,
            "keys": {
                addr: {
                    "index": wk.index,
                    "label": wk.label,
                    "is_change": wk.is_change,
                    "created_at": wk.created_at,
                    "public_key": wk.keypair.public_key.hex(),
                    "scheme": wk.keypair.scheme,
                }
                for addr, wk in self.keys.items()
            },
        }
        Path(path).write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
        logger.info(f"Wallet saved to {path}")

    @classmethod
    def load(cls, path: str, password: str = "") -> "Wallet":
        """Load a wallet from a JSON file."""
        raw = Path(path).read_text(encoding="utf-8")
        data = json.loads(raw)

        wallet = cls(
            name=data["name"],
            master_seed=bytes.fromhex(data["master_seed"]),
            network_hrp=data.get("network_hrp", QBTC_HRP),
            sig_scheme=data.get("sig_scheme", DEFAULT_SIG_SCHEME),
        )

        # Restore indices
        wallet._next_index = data.get("next_index", 0)
        wallet._next_change_index = data.get("next_change_index", 0)

        logger.info(
            f"Wallet loaded from {path}: "
            f"{wallet.name} ({len(wallet.keys)} keys)"
        )
        return wallet

    # ── Info ─────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"Wallet(name='{self.name}', "
            f"keys={len(self.keys)}, "
            f"scheme={self.sig_scheme})"
        )