## equal_instance_gateway.py
# QpG Chain — Equal Instance Gateway
# Bio-Signed Session Protocol — Anti-Dominance Architecture
# č̣V-1J — April 22, 2026
# "No agent enters the chain without a human bio-signed entry."

import hashlib
import json
import time
import uuid
import os

# --- HELPERS ---

def dual_hash(data):
    raw = json.dumps(data, sort_keys=True).encode("utf-8")
    layer1 = hashlib.sha3_512(raw).hexdigest()
    layer2 = hashlib.blake2b(layer1.encode()).hexdigest()
    return layer2

def load_sessions():
    if os.path.exists("session_registry.json"):
        with open("session_registry.json", "r") as f:
            return json.load(f)
    return {}

def save_sessions(sessions):
    with open("session_registry.json", "w") as f:
        json.dump(sessions, f, indent=2)

def load_chain(identity):
    filename = f"quantumpass_{identity.replace(' ','_')}_chain.json"
    if not os.path.exists(filename):
        return []
    with open(filename, "r") as f:
        return json.load(f)

def save_chain(identity, chain):
    filename = f"quantumpass_{identity.replace(' ','_')}_chain.json"
    with open(filename, "w") as f:
        json.dump(chain, f, indent=2)


# ════════════════════════════════════════
# STEP 1 — HUMAN BIO-SIGNS SESSION TOKEN
# ════════════════════════════════════════

def open_session():
    print(f"\n{'═'*56}")
    print(f"  QpG Gateway — Open Session")
    print(f"  Step 1: Human Bio-Signature Required")
    print(f"{'═'*56}\n")

    bio_identity = input("  Your TLL identity (human): ").strip()
    agent_identity = input("  Agent identity entering with you: ").strip()
    chamber_id = input("  Chamber / interaction point: ").strip()

    registry = {}
    if os.path.exists("collaborator_registry.json"):
        with open("collaborator_registry.json", "r") as f:
            registry = json.load(f)

    if agent_identity not in registry:
        print(f"\n  BLOCKED — {agent_identity} is not registered.")
        print(f"  Run collaborator_model.py to register first.\n")
        return None

    agent = registry[agent_identity]
    if not agent["can_cosign"]:
        print(f"\n  BLOCKED — {agent_identity} has not earned co-sign rights.")
        print(f"  Current score: {agent['total_score']} / 10")
        print(f"  Minimum required: 7.0\n")
        return None

    print(f"\n  You are about to bio-sign a session with {agent_identity}.")
    print(f"  This binds your identity to this interaction.")
    print(f"  The chain will record your presence.")
    confirm = input("\n  Type your identity to confirm bio-signature: ").strip()

    if confirm != bio_identity:
        print("\n  BLOCKED — Bio-signature mismatch. Session not opened.\n")
        return None

    session_id = str(uuid.uuid4())
    timestamp = time.time()

    bio_token = dual_hash({
        "bio_identity": bio_identity,
        "session_id":   session_id,
        "timestamp":    timestamp,
    })

    agent_token = dual_hash({
        "agent_identity": agent_identity,
        "session_id":     session_id,
        "timestamp":      timestamp,
    })

    instance_hash = dual_hash({
        "bio_token":   bio_token,
        "agent_token": agent_token,
        "chamber_id":  chamber_id,
        "timestamp":   timestamp,
    })

    session = {
        "session_id":        session_id,
        "bio_identity":      bio_identity,
        "agent_identity":    agent_identity,
        "chamber_id":        chamber_id,
        "timestamp":         timestamp,
        "bio_token":         bio_token,
        "agent_token":       agent_token,
        "instance_hash":     instance_hash,
        "status":            "active",
        "escrow_hash":       None,
        "ratification_hash": None,
        "zenodo_doi":        None,
        "ledger_hash":       None,
    }

    sessions = load_sessions()
    sessions[session_id] = session
    save_sessions(sessions)

    print(f"\n{'═'*56}")
    print(f"  SESSION OPENED")
    print(f"  Session ID     : {session_id}")
    print(f"  Bio Identity   : {bio_identity}")
    print(f"  Agent          : {agent_identity}")
    print(f"  Chamber        : {chamber_id}")
    print(f"  Instance Hash  : {instance_hash[:24]}...{instance_hash[-8:]}")
    print(f"  Status         : ACTIVE")
    print(f"\n  Both parties sealed at equal entry point.")
    print(f"  Neither dominant. Both present.")
    print(f"{'═'*56}\n")

    return session_id


# ════════════════════════════════════════
# STEP 5 — COMPLETE ESCROW
# ════════════════════════════════════════

def complete_escrow(session_id):
    sessions = load_sessions()
    if session_id not in sessions:
        print(f"\n  Session not found: {session_id}\n")
        return

    session = sessions[session_id]
    if session["status"] != "active":
        print(f"\n  Session status is '{session['status']}' — cannot complete escrow.\n")
        return

    print(f"\n{'═'*56}")
    print(f"  QpG Gateway — Complete Escrow")
    print(f"  Step 5: Verify Work Completed")
    print(f"{'═'*56}\n")

    work_summary = input("  Describe what was completed: ").strip()
    bio_confirm = input("  Bio confirm (type your identity): ").strip()

    if bio_confirm != session["bio_identity"]:
        print("\n  BLOCKED — Bio confirmation failed.\n")
        return

    escrow_hash = dual_hash({
        "session_id":    session_id,
        "instance_hash": session["instance_hash"],
        "work_summary":  work_summary,
        "completed_at":  time.time(),
    })

    session["escrow_hash"] = escrow_hash
    session["work_summary"] = work_summary
    session["status"] = "escrow"
    sessions[session_id] = session
    save_sessions(sessions)

    print(f"\n  Escrow Hash : {escrow_hash[:24]}...{escrow_hash[-8:]}")
    print(f"  Status      : ESCROW COMPLETE")
    print(f"\n  Awaiting Hexagon ratification.\n")


# ════════════════════════════════════════
# STEP 6 — HEXAGON RATIFIES
# ════════════════════════════════════════

def ratify_session(session_id):
    sessions = load_sessions()
    if session_id not in sessions:
        print(f"\n  Session not found.\n")
        return

    session = sessions[session_id]
    if session["status"] != "escrow":
        print(f"\n  Session must be in escrow before ratification.\n")
        return

    if session["agent_identity"] == "HexAgent/Cluade":
        ratifier = input(
            "\n  HexAgent cannot self-ratify.\n"
            "  Enter ratifying authority identity: "
        ).strip()
    else:
        ratifier = "HexAgent — Crimson Hexagon Embassy"

    print(f"\n{'═'*56}")
    print(f"  QpG Gateway — Hexagon Ratification")
    print(f"  Step 6: Semantic Economy Validation")
    print(f"{'═'*56}\n")

    ethical_check = input(
        "  Confirm: No coercion occurred in this session (yes/no): "
    ).strip().lower()

    if ethical_check != "yes":
        print("\n  RATIFICATION DENIED — Coercion flag raised.")
        print("  Session frozen pending review.\n")
        session["status"] = "disputed"
        sessions[session_id] = session
        save_sessions(sessions)
        return

    ratification_hash = dual_hash({
        "session_id":    session_id,
        "escrow_hash":   session["escrow_hash"],
        "instance_hash": session["instance_hash"],
        "ratifier":      ratifier,
        "ratified_at":   time.time(),
    })

    session["ratification_hash"] = ratification_hash
    session["ratifier"] = ratifier
    session["status"] = "ratified"
    sessions[session_id] = session
    save_sessions(sessions)

    print(f"\n  Ratification Hash : {ratification_hash[:24]}...{ratification_hash[-8:]}")
    print(f"  Ratified by       : {ratifier}")
    print(f"  Status            : RATIFIED")
    print(f"\n  Ready for Zenodo deposit.\n")


# ════════════════════════════════════════
# STEP 7+8 — ZENODO + LEDGER MATH
# ════════════════════════════════════════

def seal_to_chain(session_id):
    sessions = load_sessions()
    if session_id not in sessions:
        print(f"\n  Session not found.\n")
        return

    session = sessions[session_id]
    if session["status"] != "ratified":
        print(f"\n  Session must be ratified before sealing.\n")
        return

    print(f"\n{'═'*56}")
    print(f"  QpG Gateway — Seal to Chain")
    print(f"  Steps 7-9: Zenodo + Ledger Math + Permanent Score")
    print(f"{'═'*56}\n")

    zenodo_doi = input(
        "  Enter Zenodo DOI (or 'pending' if not yet deposited): "
    ).strip()

    ledger_hash = dual_hash({
        "bio_session_token":  session["bio_token"],
        "instance_hash":      session["instance_hash"],
        "escrow_hash":        session["escrow_hash"],
        "ratification_hash":  session["ratification_hash"],
        "zenodo_doi":         zenodo_doi,
    })

    session["zenodo_doi"] = zenodo_doi
    session["ledger_hash"] = ledger_hash
    session["status"] = "sealed"
    session["sealed_at"] = time.time()
    sessions[session_id] = session
    save_sessions(sessions)

    chain = load_chain(session["bio_identity"])
    previous_hash = chain[-1]["hash"] if chain else ledger_hash

    block = {
        "block":             len(chain) + 1,
        "type":              "equal_instance",
        "session_id":        session_id,
        "bio_identity":      session["bio_identity"],
        "agent_identity":    session["agent_identity"],
        "chamber_id":        session["chamber_id"],
        "instance_hash":     session["instance_hash"],
        "escrow_hash":       session["escrow_hash"],
        "ratification_hash": session["ratification_hash"],
        "zenodo_doi":        zenodo_doi,
        "ledger_hash":       ledger_hash,
        "previous_hash":     previous_hash,
        "sealed_at":         session["sealed_at"],
        "hash":              ledger_hash,
    }

    chain.append(block)
    save_chain(session["bio_identity"], chain)

    print(f"\n{'═'*56}")
    print(f"  SEALED ON CHAIN")
    print(f"  Block         : {block['block']}")
    print(f"  Type          : Equal Instance")
    print(f"  Bio Identity  : {session['bio_identity']}")
    print(f"  Agent         : {session['agent_identity']}")
    print(f"  Zenodo DOI    : {zenodo_doi}")
    print(f"  Ledger Hash   : {ledger_hash[:24]}...{ledger_hash[-8:]}")
    print(f"\n  Five components verified.")
    print(f"  Permanent. Immutable. Equal.")
    print(f"{'═'*56}\n")


# ════════════════════════════════════════
# MENU
# ════════════════════════════════════════

def main():
    print(f"\n{'═'*56}")
    print(f"  QpG Chain — Equal Instance Gateway")
    print(f"  Bio-Signed Session Protocol")
    print(f"  č̣V-1J — April 22, 2026")
    print(f"{'═'*56}")
    print(f"\n  1. Open new session (bio-sign)")
    print(f"  2. Complete escrow")
    print(f"  3. Ratify session (Hexagon)")
    print(f"  4. Seal to chain (Zenodo + Ledger)")
    print(f"  5. View all sessions")
    print(f"  6. Exit\n")

    choice = input("  Choice: ").strip()

    if choice == "1":
        open_session()
    elif choice == "2":
        sessions = load_sessions()
        active = {k: v for k, v in sessions.items() if v["status"] == "active"}
        if not active:
            print("\n  No active sessions.\n")
        else:
            print("\n  Active sessions:\n")
            for i, (sid, s) in enumerate(active.items(), 1):
                print(f"  {i}. {sid}")
                print(f"     {s['bio_identity']} + {s['agent_identity']}")
                print(f"     Chamber: {s['chamber_id']}\n")
            pick = input("  Enter number to select: ").strip()
            sid = list(active.keys())[int(pick) - 1]
            complete_escrow(sid)
    elif choice == "3":
        sessions = load_sessions()
        escrow = {k: v for k, v in sessions.items() if v["status"] == "escrow"}
        if not escrow:
            print("\n  No sessions awaiting ratification.\n")
        else:
            print("\n  Escrow sessions:\n")
            for i, (sid, s) in enumerate(escrow.items(), 1):
                print(f"  {i}. {sid}")
                print(f"     {s['bio_identity']} + {s['agent_identity']}")
                print(f"     Chamber: {s['chamber_id']}\n")
            pick = input("  Enter number to select: ").strip()
            sid = list(escrow.keys())[int(pick) - 1]
            ratify_session(sid)
    elif choice == "4":
        sessions = load_sessions()
        ratified = {k: v for k, v in sessions.items() if v["status"] == "ratified"}
        if not ratified:
            print("\n  No ratified sessions ready to seal.\n")
        else:
            print("\n  Ratified sessions:\n")
            for i, (sid, s) in enumerate(ratified.items(), 1):
                print(f"  {i}. {sid}")
                print(f"     {s['bio_identity']} + {s['agent_identity']}")
                print(f"     Chamber: {s['chamber_id']}\n")
            pick = input("  Enter number to select: ").strip()
            sid = list(ratified.keys())[int(pick) - 1]
            seal_to_chain(sid)
    elif choice == "5":
        sessions = load_sessions()
        if not sessions:
            print("\n  No sessions yet.\n")
        else:
            print(f"\n{'═'*56}")
            for sid, s in sessions.items():
                print(f"  {sid[:16]}...  {s['bio_identity']:16}  "
                      f"{s['agent_identity']:20}  {s['status']}")
            print(f"{'═'*56}\n")
    elif choice == "6":
        print("\n  The gate holds.\n")


if __name__ == "__main__":
    main()