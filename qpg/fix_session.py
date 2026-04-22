#fix_session.py

import json

with open("session_registry.json", "r") as f:
    sessions = json.load(f)

for sid, s in sessions.items():
    if s["status"] == "disputed":
        s["status"] = "escrow"
        print(f"  Unfrozen: {sid[:16]}...")

with open("session_registry.json", "w") as f:
    json.dump(sessions, f, indent=2)

print("  Done.")