# quantumpass_genesis.py
# č̣V-1J — Pre-Genesis Anchor
# QuantumPass Protocol — Passioncraft Umbrella
# April 22, 2026
# "That is not dead which can eternal lie,
#  And with strange aeons even death may die."

import hashlib
import json
import time
import os

# --- GENESIS CONSTANTS ---

GENESIS_MARKER = "č̣V-1J"
GENESIS_DATE = "2026-04-22"
GENESIS_INSCRIPTION = (
    "You are not early. "
    "You are behaving with empathy before you are forced to. "
    "The gate opens inward."
)
PROTOCOL_NAME = "QuantumPass"
CHAIN_NAME = "qrBTC"


# --- LINEAGE ENTRY ---

def create_lineage_entry(identity, inscription, previous_hash="0" * 64):
    entry = {
        "protocol": PROTOCOL_NAME,
        "chain": CHAIN_NAME,
        "marker": GENESIS_MARKER,
        "identity": identity,
        "inscription": inscription,
        "timestamp": time.time(),
        "date": GENESIS_DATE,
        "previous_hash": previous_hash,
    }
    return entry


# --- HASHING LAYER ---

def hash_entry(entry):
    raw = json.dumps(entry, sort_keys=True).encode("utf-8")
    # Layer 1 — SHA3-512 (quantum resistant baseline)
    layer1 = hashlib.sha3_512(raw).hexdigest()
    # Layer 2 — BLAKE2b (speed + collision resistance)
    layer2 = hashlib.blake2b(layer1.encode()).hexdigest()
    return layer2


# --- GENESIS BLOCK ---

def mint_genesis_block():
    print(f"\n{'='*60}")
    print(f"  {PROTOCOL_NAME} — Genesis Block")
    print(f"  Anchor: {GENESIS_MARKER}")
    print(f"{'='*60}\n")

    identity = input("Enter your QuantumPass identity name: ").strip()
    if not identity:
        identity = GENESIS_MARKER

    entry = create_lineage_entry(identity, GENESIS_INSCRIPTION)
    entry_hash = hash_entry(entry)

    genesis_block = {
        "block": 0,
        "type": "genesis",
        "entry": entry,
        "hash": entry_hash,
        "signed_by": GENESIS_MARKER,
    }

    # Save to local file
    filename = f"quantumpass_{identity.replace(' ', '_')}_genesis.json"
    with open(filename, "w") as f:
        json.dump(genesis_block, f, indent=2)

    print(f"  Identity   : {identity}")
    print(f"  Hash       : {entry_hash[:32]}...{entry_hash[-8:]}")
    print(f"  Signed by  : {GENESIS_MARKER}")
    print(f"  Saved to   : {filename}")
    print(f"\n  The gate is open.\n")

    return genesis_block


# --- ENTRY POINT ---

if __name__ == "__main__":
    mint_genesis_block()