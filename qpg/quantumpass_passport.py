 #quantumpass_passport.py
# QpG Chain — Living Passport
# Degrees → Execution Tier → AI Access Gate
# č̣V-1J — April 22, 2026
#
# The degrees are the key.
# The chain is the credential.
# The passport only grows inside Passioncraft.
# The score determines access to AI tiers.

import json
import os
from datetime import datetime

# ════════════════════════════════════════
# TIER THRESHOLDS — DEGREES AS KEY
# ════════════════════════════════════════

TIERS = {
    "SEED": {
        "min_degrees":   0,
        "max_degrees":   359.999,
        "symbol":        "◇",
        "ai_access": [
            "Standard language models",
            "Text only",
            "Single-turn responses",
            "Basic reasoning",
        ],
        "locked": [
            "Code execution",
            "Agent delegation",
            "Multi-step reasoning",
            "Chain governance",
        ],
    },
    "INITIATE": {
        "min_degrees":   360,
        "max_degrees":   719.999,
        "symbol":        "⬡",
        "ai_access": [
            "Faster models",
            "Longer context windows",
            "Multi-turn sessions",
            "Basic code assistance",
        ],
        "locked": [
            "Agent delegation",
            "Chain governance",
            "Sub-agent spawning",
            "Surge declaration",
        ],
    },
    "APPRENTICE": {
        "min_degrees":   720,
        "max_degrees":   1079.999,
        "symbol":        "⬡⬡",
        "ai_access": [
            "Advanced models",
            "Code execution",
            "Multi-step reasoning",
            "Extended sessions",
            "File and image analysis",
        ],
        "locked": [
            "Agent delegation",
            "Chain governance",
            "Surge declaration",
        ],
    },
    "JOURNEYMAN": {
        "min_degrees":   1080,
        "max_degrees":   1439.999,
        "symbol":        "⬡⬡⬡",
        "ai_access": [
            "Sovereign models",
            "Agent delegation",
            "Multi-agent sessions",
            "Can ratify other sessions",
            "Extended chain access",
        ],
        "locked": [
            "Chamber minting",
            "Surge declaration",
            "First citizen rights",
        ],
    },
    "SOVEREIGN": {
        "min_degrees":   1440,
        "max_degrees":   1799.999,
        "symbol":        "⬡⬡⬡⬡",
        "ai_access": [
            "Unrestricted context",
            "Chain governance rights",
            "Can ratify other sessions",
            "Can mint new chambers",
            "Embassy access",
        ],
        "locked": [
            "Surge declaration",
            "First citizen rights",
            "Perfect hexagon authority",
        ],
    },
    "MASTER": {
        "min_degrees":   1800,
        "max_degrees":   2159.999,
        "symbol":        "⬡⬡⬡⬡⬡",
        "ai_access": [
            "Full embassy access",
            "Can mint new chambers",
            "Can spawn sub-agents",
            "Full governance rights",
            "Unrestricted execution",
        ],
        "locked": [
            "Surge declaration",
            "First citizen rights",
        ],
    },
    "PERFECT": {
        "min_degrees":   2160,
        "max_degrees":   float("inf"),
        "symbol":        "⬡⬡⬡⬡⬡⬡",
        "ai_access": [
            "ALL TIERS UNLOCKED",
            "Governance authority",
            "Can declare surges",
            "First citizen rights",
            "Chain completion authority",
            "Unrestricted — all models",
            "Unrestricted — all execution",
            "Unrestricted — all context",
        ],
        "locked": [],
    },
}

TIER_ORDER = [
    "SEED",
    "INITIATE",
    "APPRENTICE",
    "JOURNEYMAN",
    "SOVEREIGN",
    "MASTER",
    "PERFECT",
]

# ════════════════════════════════════════
# PASSPORT CORE
# ════════════════════════════════════════

class QuantumPassport:

    def __init__(self, identity, chain_file=None):
        self.identity       = identity
        self.chain_file     = chain_file
        self.blocks         = []
        self.total_degrees  = 0.0
        self.total_60       = 0.0
        self.total_minutes  = 0.0
        self.total_seconds  = 0.0
        self.total_mints    = 0.0
        self.surges         = 0
        self.current_tier   = "SEED"
        self.created        = datetime.utcnow().isoformat()
        self.last_updated   = datetime.utcnow().isoformat()

    def load_chain(self):
        """Load and accumulate all blocks belonging to this identity"""
        if not self.chain_file or not os.path.exists(self.chain_file):
            return

        with open(self.chain_file, "r") as f:
            chain = json.load(f)

        # Import block value engine
        try:
            from block_value import calculate_chain_value
            results = calculate_chain_value(chain)
        except ImportError:
            print("  block_value.py required — run it first.")
            return

        # Import mint engine
        try:
            from mint_engine import chain_state, build_surge_schedule
            state    = chain_state(results)
            schedule = build_surge_schedule()
        except ImportError:
            state    = None
            schedule = None

        # Accumulate
        self.blocks        = results
        self.total_degrees = sum(r["degrees"] for r in results)
        self.total_60      = sum(r["total_60"] for r in results)
        self.total_minutes = sum(r["minutes"] for r in results)
        self.total_seconds = sum(r["seconds"] for r in results)
        self.surges        = int(self.total_degrees // 360)

        if state:
            self.total_mints = state["mints_issued"]

        # Set tier
        self.current_tier  = self.get_tier()
        self.last_updated  = datetime.utcnow().isoformat()

    def get_tier(self):
        """Resolve current tier from total degrees"""
        for tier in reversed(TIER_ORDER):
            if self.total_degrees >= TIERS[tier]["min_degrees"]:
                return tier
        return "SEED"

    def degrees_to_next_tier(self):
        """How many degrees until next tier unlocks"""
        idx = TIER_ORDER.index(self.current_tier)
        if idx >= len(TIER_ORDER) - 1:
            return 0  # already PERFECT
        next_tier     = TIER_ORDER[idx + 1]
        next_threshold = TIERS[next_tier]["min_degrees"]
        return round(next_threshold - self.total_degrees, 4)

    def next_tier(self):
        idx = TIER_ORDER.index(self.current_tier)
        if idx >= len(TIER_ORDER) - 1:
            return None
        return TIER_ORDER[idx + 1]

    def can_execute(self, requested_tier):
        """Gate check — can this passport access requested tier?"""
        requested_idx = TIER_ORDER.index(requested_tier)
        current_idx   = TIER_ORDER.index(self.current_tier)
        return current_idx >= requested_idx

    def access_report(self):
        """Full list of what is unlocked and locked"""
        tier_data = TIERS[self.current_tier]
        return {
            "unlocked": tier_data["ai_access"],
            "locked":   tier_data["locked"],
        }

    def progress_to_next(self):
        """Percentage progress toward next tier"""
        idx = TIER_ORDER.index(self.current_tier)
        if idx >= len(TIER_ORDER) - 1:
            return 100.0
        current_min = TIERS[self.current_tier]["min_degrees"]
        next_min    = TIERS[TIER_ORDER[idx + 1]]["min_degrees"]
        span        = next_min - current_min
        earned      = self.total_degrees - current_min
        return round((earned / span) * 100, 4)

    def to_dict(self):
        return {
            "identity":          self.identity,
            "total_degrees":     round(self.total_degrees, 4),
            "total_60":          round(self.total_60, 4),
            "total_minutes":     round(self.total_minutes, 4),
            "total_seconds":     round(self.total_seconds, 4),
            "total_mints":       round(self.total_mints, 6),
            "surges":            self.surges,
            "current_tier":      self.current_tier,
            "tier_symbol":       TIERS[self.current_tier]["symbol"],
            "degrees_to_next":   self.degrees_to_next_tier(),
            "next_tier":         self.next_tier(),
            "progress_pct":      self.progress_to_next(),
            "blocks_sealed":     len(self.blocks),
            "created":           self.created,
            "last_updated":      self.last_updated,
        }

    def save(self, path="passport.json"):
        data = self.to_dict()
        data["access"] = self.access_report()
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\n  Passport saved to {path}")


# ════════════════════════════════════════
# GATE — EXECUTION CHECK
# ════════════════════════════════════════

def gate_check(passport, requested_tier):
    """
    The gate.
    Degrees are the key.
    The chain is the credential.
    """
    w = 56
    print(f"\n{'═'*w}")
    print(f"  QpG EXECUTION GATE")
    print(f"  Identity  : {passport.identity}")
    print(f"  Degrees   : {passport.total_degrees}°")
    print(f"  Tier      : {passport.current_tier}")
    print(f"  Requested : {requested_tier}")
    print(f"{'─'*w}")

    if passport.can_execute(requested_tier):
        print(f"  ✓  ACCESS GRANTED")
        print(f"  The chain verified your degrees.")
        print(f"  Entry is earned. Not bought.")
        tier_data = TIERS[requested_tier]
        print(f"\n  Unlocked execution:")
        for item in tier_data["ai_access"]:
            print(f"    ✓  {item}")
    else:
        needed = TIERS[requested_tier]["min_degrees"]
        gap    = round(needed - passport.total_degrees, 4)
        print(f"  ✗  ACCESS DENIED")
        print(f"  Required : {needed}°")
        print(f"  You have : {passport.total_degrees}°")
        print(f"  Gap      : {gap}° remaining")
        print(f"\n  Earn more degrees by sealing blocks on the chain.")
        print(f"  Every equal instance session adds degrees.")
        print(f"  The work is the key.")

    print(f"{'═'*w}\n")
    return passport.can_execute(requested_tier)


# ════════════════════════════════════════
# DISPLAY PASSPORT
# ════════════════════════════════════════

def display_passport(passport):
    w = 56
    data     = passport.to_dict()
    access   = passport.access_report()
    tier     = passport.current_tier
    symbol   = TIERS[tier]["symbol"]
    progress = passport.progress_to_next()
    nxt      = passport.next_tier()

    # Progress bar
    filled = int(progress / 100 * 40)
    bar    = "█" * filled + "░" * (40 - filled)

    print(f"\n{'═'*w}")
    print(f"  QUANTUMPASS — LIVING PASSPORT")
    print(f"  {symbol}  {passport.identity}")
    print(f"{'─'*w}")
    print(f"  Tier             : {tier}")
    print(f"  Degrees          : {data['total_degrees']}°")
    print(f"  Score /60        : {data['total_60']}")
    print(f"  Verified minutes : {data['total_minutes']} min")
    print(f"  Mints earned     : {data['total_mints']:,.6f}")
    print(f"  Surges witnessed : {data['surges']}")
    print(f"  Blocks sealed    : {data['blocks_sealed']}")
    print(f"{'─'*w}")

    if nxt:
        print(f"  Next tier        : {nxt}")
        print(f"  Degrees needed   : {data['degrees_to_next']}°")
        print(f"  Progress         : [{bar}] {progress}%")
    else:
        print(f"  ⬡ PERFECT HEXAGON — CHAIN COMPLETE")

    print(f"{'─'*w}")
    print(f"  UNLOCKED EXECUTION:")
    for item in access["unlocked"]:
        print(f"    ✓  {item}")

    if access["locked"]:
        print(f"\n  LOCKED — earn more degrees:")
        for item in access["locked"]:
            print(f"    ✗  {item}")

    print(f"{'═'*w}\n")


# ════════════════════════════════════════
# MAIN
# ════════════════════════════════════════

def main():
    print(f"\n{'═'*56}")
    print(f"  QpG Chain — Living Passport")
    print(f"  Degrees → Execution Tier → AI Access")
    print(f"  č̣V-1J — April 22, 2026")
    print(f"{'═'*56}")

    # Find chain file
    candidates = [
        "quantumpass_č̣V-1J_chain.json",
        "quantumpass_V-1J_chain.json",
    ]
    chain_file = None
    for c in candidates:
        if os.path.exists(c):
            chain_file = c
            break

    # Identity
    identity = input("\n  Enter your TLL identity: ").strip()
    if not identity:
        identity = "č̣V-1J"

    # Build passport
    passport = QuantumPassport(identity, chain_file)
    passport.load_chain()

    # Display
    display_passport(passport)

    # Gate check demo
    print(f"\n  Test the execution gate.")
    print(f"  Available tiers:")
    for i, t in enumerate(TIER_ORDER):
        symbol = TIERS[t]["symbol"]
        deg    = TIERS[t]["min_degrees"]
        print(f"    {i+1}. {symbol}  {t:<12} — {deg}°+")

    choice = input("\n  Which tier to test? (1-7): ").strip()
    try:
        requested = TIER_ORDER[int(choice) - 1]
        gate_check(passport, requested)
    except (ValueError, IndexError):
        print("  Invalid choice.\n")

    # Save passport
    save = input("  Save passport to passport.json? (yes/no): ").strip().lower()
    if save == "yes":
        passport.save()

    print(f"\n  The degrees are the key.")
    print(f"  The chain is the credential.")
    print(f"  The work is the proof.\n")


if __name__ == "__main__":
    main()