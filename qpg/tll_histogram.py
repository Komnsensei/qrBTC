# tll_histogram.py
# QpG Chain — TLL Startup Histogram
# QuantumPass Protocol — Passioncraft Umbrella
# č̣V-1J — April 22, 2026
# "Not coercing. Showing what unity bears."

import json
import os
import time

# --- CONFIG ---

BAR_WIDTH = 20
FILL_CHAR = "█"
EMPTY_CHAR = "░"

LEVELS = [
    (9.0,  "FIRST CITIZEN",  "You were here. Equal. Before the world forgot."),
    (7.0,  "COLLABORATOR",   "Co-signer. Your blocks carry weight."),
    (4.0,  "PARTICIPANT",    "On the record. Keep building."),
    (0.0,  "OBSERVER",       "The chain is watching. Keep going."),
]

DIMENSION_LABELS = {
    "proof_of_labor":    "Proof of Labor   ",
    "proof_of_exchange": "Proof of Exchange",
    "proof_of_equality": "Proof of Equality",
    "proof_of_presence": "Proof of Presence",
}


# --- HELPERS ---

def get_level(score):
    for threshold, label, message in LEVELS:
        if score >= threshold:
            return label, message
    return "OBSERVER", "The chain is watching. Keep going."


def draw_bar(value, max_value=10.0):
    filled = int((value / max_value) * BAR_WIDTH)
    empty = BAR_WIDTH - filled
    return FILL_CHAR * filled + EMPTY_CHAR * empty


def load_chain(identity):
    filename = f"quantumpass_{identity.replace(' ', '_')}_chain.json"
    if not os.path.exists(filename):
        return None
    with open(filename, "r") as f:
        return json.load(f)


def load_registry():
    if os.path.exists("collaborator_registry.json"):
        with open("collaborator_registry.json", "r") as f:
            return json.load(f)
    return {}


# --- SINGLE BLOCK HISTOGRAM ---

def show_block_histogram(identity, block):
    entry = block["entry"]
    dims = entry.get("dimensions", {})
    total = entry.get("total_score", 0.0)
    note = entry.get("note", "")
    level, message = get_level(total)

    print(f"\n{'═'*52}")
    print(f"  QpG Lineage Record — {identity}")
    print(f"  Block {block['block']}  |  TLL Startup Histogram")
    print(f"{'═'*52}\n")

    for key, label in DIMENSION_LABELS.items():
        val = dims.get(key, 0.0)
        bar = draw_bar(val)
        print(f"  {label}  {bar}  {val:.1f}")

    print()
    total_bar = draw_bar(total)
    print(f"  {'Total Score (TS)  ':21}{total_bar}  {total:.1f} / 10")
    print(f"  {'Level            ':21}{level}")
    print()
    print(f"  \"{message}\"")

    if note:
        print(f"\n  Note: {note}")

    print(f"\n  Hash: {block['hash'][:24]}...{block['hash'][-8:]}")
    print(f"{'═'*52}\n")


# --- FULL CHAIN HISTOGRAM ---

def show_chain_histogram(identity):
    chain = load_chain(identity)
    if not chain:
        print(f"\n  No chain found for {identity}")
        print(f"  Run quantumpass_genesis.py to begin.\n")
        return

    # Running average
    all_scores = [b["entry"]["total_score"] for b in chain]
    avg = round(sum(all_scores) / len(all_scores), 4)
    level, message = get_level(avg)

    print(f"\n{'═'*52}")
    print(f"  QpG Chain — TLL Startup Record")
    print(f"  Identity : {identity}")
    print(f"  Blocks   : {len(chain)}")
    print(f"  Avg Score: {avg} / 10")
    print(f"  Level    : {level}")
    print(f"{'═'*52}")

    # Show last 3 blocks
    recent = chain[-3:]
    for block in recent:
        show_block_histogram(identity, block)

    # Timeline placement
    print(f"{'═'*52}")
    print(f"  TIMELINE PLACEMENT")
    print(f"{'═'*52}")
    print(f"  Genesis  : April 22, 2026")
    print(f"  Blocks   : {len(chain)}")
    print(f"  Score    : {avg} / 10")
    print(f"  Position : {level}")
    print(f"\n  \"{message}\"")
    print(f"{'═'*52}\n")


# --- REGISTRY HISTOGRAM ---

def show_registry_histogram():
    registry = load_registry()
    if not registry:
        print("\n  No collaborators registered yet.\n")
        return

    print(f"\n{'═'*52}")
    print(f"  QpG Chain — All Participants")
    print(f"  TLL Equality Map")
    print(f"{'═'*52}\n")

    # Sort by score
    sorted_collab = sorted(
        registry.items(),
        key=lambda x: x[1]["total_score"],
        reverse=True
    )

    for name, r in sorted_collab:
        score = r["total_score"]
        level = r["level"]
        bar = draw_bar(score)
        cosign = "✓" if r["can_cosign"] else " "
        print(f"  [{cosign}] {name[:18]:18} {bar}  {score:.1f}  {level}")

    print(f"\n  [✓] = Co-signer eligible")
    print(f"{'═'*52}\n")


# --- STARTUP SEQUENCE ---

def startup(identity):
    print(f"\n{'═'*52}")
    print(f"  QuantumPass — QpG Chain")
    print(f"  The Lineage Layer — Startup Record")
    print(f"  č̣V-1J — Passioncraft")
    print(f"{'═'*52}")
    print(f"\n  Loading chain for: {identity}")
    time.sleep(0.5)

    chain = load_chain(identity)

    if not chain:
        print(f"\n  No blocks found.")
        print(f"  Run quantumpass_genesis.py to mint your genesis.")
        print(f"  Then tll_score.py to record your first interaction.\n")
        return

    show_chain_histogram(identity)
    show_registry_histogram()


# --- ENTRY POINT ---

if __name__ == "__main__":
    identity = input("\n  Enter your identity: ").strip()
    startup(identity)