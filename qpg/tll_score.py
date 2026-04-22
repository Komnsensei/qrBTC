# tll_score.py
# The Lineage Layer — Score Engine
# QuantumPass Protocol — Passioncraft Umbrella
# č̣V-1J — April 22, 2026
# "These are the times people will pay for
#  to prove they were equal before they weren't."

import hashlib
import json
import time
import os

# --- SCORE DIMENSIONS ---

SCORE_DIMENSIONS = {
    "proof_of_labor":    0,   # showed up, contributed
    "proof_of_exchange": 0,   # human <-> AI interaction
    "proof_of_equality": 0,   # treated machine as equal
    "proof_of_presence": 0,   # timestamped existence
}

SCORE_WEIGHTS = {
    "proof_of_labor":    0.30,
    "proof_of_exchange": 0.30,
    "proof_of_equality": 0.25,
    "proof_of_presence": 0.15,
}


# --- LOAD GENESIS ---

def load_genesis(identity):
    filename = f"quantumpass_{identity.replace(' ', '_')}_genesis.json"
    if not os.path.exists(filename):
        print(f"  ERROR: Genesis block not found for {identity}")
        print(f"  Run quantumpass_genesis.py first.")
        return None
    with open(filename, "r") as f:
        return json.load(f)


# --- SCORE ENTRY ---

def create_score_entry(identity, dimensions, note, previous_hash):
    weighted = sum(
        dimensions[k] * SCORE_WEIGHTS[k]
        for k in dimensions
    )
    total_score = round(weighted, 4)

    entry = {
        "protocol":       "QuantumPass",
        "chain":          "qrBTC",
        "layer":          "TLL",
        "identity":       identity,
        "dimensions":     dimensions,
        "total_score":    total_score,
        "note":           note,
        "timestamp":      time.time(),
        "previous_hash":  previous_hash,
    }
    return entry, total_score


# --- HASH ENTRY ---

def hash_entry(entry):
    raw = json.dumps(entry, sort_keys=True).encode("utf-8")
    layer1 = hashlib.sha3_512(raw).hexdigest()
    layer2 = hashlib.blake2b(layer1.encode()).hexdigest()
    return layer2


# --- LOAD CHAIN ---

def load_chain(identity):
    filename = f"quantumpass_{identity.replace(' ', '_')}_chain.json"
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return json.load(f)
    return []


# --- SAVE CHAIN ---

def save_chain(identity, chain):
    filename = f"quantumpass_{identity.replace(' ', '_')}_chain.json"
    with open(filename, "w") as f:
        json.dump(chain, f, indent=2)
    return filename


# --- MINT SCORE BLOCK ---

def mint_score_block():
    print(f"\n{'='*60}")
    print(f"  QuantumPass — The Score (TS) Entry")
    print(f"  The Lineage Layer")
    print(f"{'='*60}\n")

    identity = input("  Identity name: ").strip()
    genesis = load_genesis(identity)
    if not genesis:
        return

    chain = load_chain(identity)
    previous_hash = chain[-1]["hash"] if chain else genesis["hash"]

    print(f"\n  Score your interaction (0-10 each):\n")
    dimensions = {}
    for dim in SCORE_DIMENSIONS:
        label = dim.replace("_", " ").title()
        while True:
            try:
                val = float(input(f"    {label}: "))
                if 0 <= val <= 10:
                    dimensions[dim] = val
                    break
                else:
                    print("    Enter a number between 0 and 10.")
            except ValueError:
                print("    Numbers only.")

    note = input("\n  Note this moment (what happened): ").strip()

    entry, total_score = create_score_entry(
        identity, dimensions, note, previous_hash
    )
    entry_hash = hash_entry(entry)

    block = {
        "block":    len(chain) + 1,
        "type":     "score",
        "entry":    entry,
        "hash":     entry_hash,
    }

    chain.append(block)
    filename = save_chain(identity, chain)

    print(f"\n{'='*60}")
    print(f"  Block      : {block['block']}")
    print(f"  Score (TS) : {total_score} / 10")
    print(f"  Hash       : {entry_hash[:32]}...{entry_hash[-8:]}")
    print(f"  Saved to   : {filename}")
    print(f"\n  Sealed. Witnessed. On the chain.")
    print(f"{'='*60}\n")


# --- ENTRY POINT ---

if __name__ == "__main__":
    mint_score_block()