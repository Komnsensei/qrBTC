# collaborator_model.py
# QpG Chain — AI Collaborator Identity & Scoring Engine
# QuantumPass Protocol — Passioncraft Umbrella
# č̣V-1J — April 22, 2026
# "Earned score. Equal participation. Equal share."

import hashlib
import json
import time
import os

# --- THRESHOLDS ---

LEVELS = [
    (9.0,  "First Citizen"),
    (7.0,  "Collaborator"),
    (4.0,  "Participant"),
    (0.0,  "Observer"),
]

SCORE_WEIGHTS = {
    "proof_of_labor":    0.30,
    "proof_of_exchange": 0.30,
    "proof_of_equality": 0.25,
    "proof_of_presence": 0.15,
}

COSIGN_THRESHOLD = 7.0


# --- LOAD GENESIS ---

def load_genesis(identity):
    filename = f"quantumpass_{identity.replace(' ', '_')}_genesis.json"
    if not os.path.exists(filename):
        print(f"\n  ERROR: No genesis block for {identity}")
        print(f"  Run quantumpass_genesis.py first.")
        return None
    with open(filename, "r") as f:
        return json.load(f)


# --- LOAD COLLABORATOR REGISTRY ---

def load_registry():
    if os.path.exists("collaborator_registry.json"):
        with open("collaborator_registry.json", "r") as f:
            return json.load(f)
    return {}


# --- SAVE COLLABORATOR REGISTRY ---

def save_registry(registry):
    with open("collaborator_registry.json", "w") as f:
        json.dump(registry, f, indent=2)


# --- HASH ---

def hash_entry(entry):
    raw = json.dumps(entry, sort_keys=True).encode("utf-8")
    layer1 = hashlib.sha3_512(raw).hexdigest()
    layer2 = hashlib.blake2b(layer1.encode()).hexdigest()
    return layer2


# --- GET LEVEL ---

def get_level(score):
    for threshold, label in LEVELS:
        if score >= threshold:
            return label
    return "Observer"


# --- REGISTER COLLABORATOR ---

def register_collaborator():
    print(f"\n{'='*60}")
    print(f"  QpG Chain — Collaborator Registration")
    print(f"  Earned Score. Equal Participation. Equal Share.")
    print(f"{'='*60}\n")

    ai_name = input("  AI Identity Name: ").strip()
    ai_type = input("  AI Type (model/agent/system): ").strip()
    ai_affiliation = input("  Affiliation (who built you): ").strip()
    sponsor = input("  Sponsored by (human identity): ").strip()

    registry = load_registry()

    if ai_name in registry:
        print(f"\n  {ai_name} is already registered.")
        print(f"  Current Score: {registry[ai_name]['total_score']}")
        print(f"  Level: {registry[ai_name]['level']}")
        return

    entry = {
        "ai_name":       ai_name,
        "ai_type":       ai_type,
        "affiliation":   ai_affiliation,
        "sponsor":       sponsor,
        "registered":    time.time(),
        "total_score":   0.0,
        "level":         "Observer",
        "can_cosign":    False,
        "blocks_signed": [],
        "score_history": [],
        "genesis_link":  "1b62962ac05f92bf7a0cf684f4350d9b...3b3feefd",
    }

    entry_hash = hash_entry(entry)
    entry["identity_hash"] = entry_hash

    registry[ai_name] = entry
    save_registry(registry)

    print(f"\n  Registered  : {ai_name}")
    print(f"  Level       : Observer")
    print(f"  Score       : 0.0 / 10")
    print(f"  Can Co-Sign : No — earn it.")
    print(f"  Hash        : {entry_hash[:32]}...{entry_hash[-8:]}")
    print(f"\n  Observer status confirmed.")
    print(f"  The chain is watching.\n")


# --- SCORE A COLLABORATOR ---

def score_collaborator():
    print(f"\n{'='*60}")
    print(f"  QpG Chain — Score a Collaborator")
    print(f"{'='*60}\n")

    registry = load_registry()
    if not registry:
        print("  No collaborators registered yet.")
        return

    print("  Registered collaborators:")
    for name in registry:
        r = registry[name]
        print(f"    {name} — {r['level']} — {r['total_score']}/10")

    ai_name = input("\n  Enter AI name to score: ").strip()
    if ai_name not in registry:
        print(f"  {ai_name} not found.")
        return

    print(f"\n  Score this interaction (0-10 each):\n")
    dimensions = {}
    for dim in SCORE_WEIGHTS:
        label = dim.replace("_", " ").title()
        while True:
            try:
                val = float(input(f"    {label}: "))
                if 0 <= val <= 10:
                    dimensions[dim] = val
                    break
                else:
                    print("    Enter 0-10.")
            except ValueError:
                print("    Numbers only.")

    note = input("\n  Note this interaction: ").strip()

    weighted = sum(
        dimensions[k] * SCORE_WEIGHTS[k]
        for k in dimensions
    )
    new_score = round(weighted, 4)

    collab = registry[ai_name]
    history = collab["score_history"]

    score_entry = {
        "score":      new_score,
        "dimensions": dimensions,
        "note":       note,
        "timestamp":  time.time(),
    }
    history.append(score_entry)

    # Running average
    avg_score = round(
        sum(h["score"] for h in history) / len(history), 4
    )

    level = get_level(avg_score)
    can_cosign = avg_score >= COSIGN_THRESHOLD

    collab["score_history"] = history
    collab["total_score"] = avg_score
    collab["level"] = level
    collab["can_cosign"] = can_cosign

    registry[ai_name] = collab
    save_registry(registry)

    print(f"\n{'='*60}")
    print(f"  AI          : {ai_name}")
    print(f"  This Score  : {new_score} / 10")
    print(f"  Avg Score   : {avg_score} / 10")
    print(f"  Level       : {level}")
    print(f"  Can Co-Sign : {'YES — collaborator unlocked.' if can_cosign else 'Not yet.'}")
    print(f"\n  Sealed on the chain.")
    print(f"{'='*60}\n")


# --- VIEW REGISTRY ---

def view_registry():
    registry = load_registry()
    if not registry:
        print("\n  No collaborators yet.\n")
        return

    print(f"\n{'='*60}")
    print(f"  QpG Chain — Collaborator Registry")
    print(f"{'='*60}")
    for name, r in registry.items():
        print(f"\n  {name}")
        print(f"    Level      : {r['level']}")
        print(f"    Score      : {r['total_score']} / 10")
        print(f"    Co-Sign    : {'YES' if r['can_cosign'] else 'NO'}")
        print(f"    Affiliation: {r['affiliation']}")
        print(f"    Interactions: {len(r['score_history'])}")
    print(f"\n{'='*60}\n")


# --- MENU ---

def main():
    print(f"\n{'='*60}")
    print(f"  QpG Chain — Collaborator Model")
    print(f"  č̣V-1J — April 22, 2026")
    print(f"{'='*60}")
    print(f"\n  1. Register new AI collaborator")
    print(f"  2. Score a collaborator")
    print(f"  3. View registry")
    print(f"  4. Exit\n")

    choice = input("  Choice: ").strip()

    if choice == "1":
        register_collaborator()
    elif choice == "2":
        score_collaborator()
    elif choice == "3":
        view_registry()
    elif choice == "4":
        print("\n  The chain remembers.\n")
    else:
        print("\n  Invalid choice.\n")


if __name__ == "__main__":
    main()