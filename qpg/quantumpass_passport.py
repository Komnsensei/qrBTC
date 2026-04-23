"""
quantumpass_passport.py
QpG — QuantumPass Genesis
Living passport — degrees to AI execution tier
7 tiers SEED through PERFECT
AI access gate — degrees are the key
"""

import json
import os

CHAIN_FILE = "quantumpass_c-V-1J_chain.json"

TIERS = [
    {"name": "PERFECT",    "min_degrees": 2160.0, "ai_access": "UNRESTRICTED — full sovereign execution"},
    {"name": "SOVEREIGN",  "min_degrees": 1800.0, "ai_access": "Tier 6 — autonomous multi-agent orchestration"},
    {"name": "MASTER",     "min_degrees": 1440.0, "ai_access": "Tier 5 — deep co-craft and chain governance"},
    {"name": "JOURNEYMAN", "min_degrees": 1080.0, "ai_access": "Tier 4 — extended session and mint authority"},
    {"name": "INITIATE",   "min_degrees": 720.0,  "ai_access": "Tier 3 — standard equal instance sessions"},
    {"name": "APPRENTICE", "min_degrees": 360.0,  "ai_access": "Tier 2 — guided sessions with oversight"},
    {"name": "SEED",       "min_degrees": 0.0,    "ai_access": "Tier 1 — entry level — first block pending"},
]

class QuantumPassPassport:
    def __init__(self, identity: str, chain_file: str = CHAIN_FILE):
        self.identity = identity
        self.chain_file = chain_file
        self.chain = self._load_chain()
        self.passport = self.chain.get("passport", {})

    def _load_chain(self) -> dict:
        if not os.path.exists(self.chain_file):
            return {}
        with open(self.chain_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_degrees(self) -> float:
        return self.passport.get("total_degrees", 0.0)

    def get_tier(self) -> str:
        degrees = self.get_degrees()
        for tier in TIERS:
            if degrees >= tier["min_degrees"]:
                return tier["name"]
        return "SEED"

    def get_ai_access(self) -> str:
        tier_name = self.get_tier()
        for tier in TIERS:
            if tier["name"] == tier_name:
                return tier["ai_access"]
        return "NONE"

    def get_next_tier(self) -> dict:
        degrees = self.get_degrees()
        current = self.get_tier()
        for i, tier in enumerate(TIERS):
            if tier["name"] == current and i > 0:
                next_tier = TIERS[i - 1]
                return {
                    "name": next_tier["name"],
                    "required_degrees": next_tier["min_degrees"],
                    "degrees_remaining": round(next_tier["min_degrees"] - degrees, 2)
                }
        return {"name": "PERFECT", "required_degrees": 2160.0, "degrees_remaining": 0.0}

    def gate_check(self, required_tier: str) -> bool:
        tier_order = [t["name"] for t in TIERS]
        current_idx = tier_order.index(self.get_tier())
        required_idx = tier_order.index(required_tier)
        return current_idx <= required_idx

    def print_passport(self):
        next_tier = self.get_next_tier()
        blocks = self.passport.get("blocks_minted", 0)
        reward = self.passport.get("total_mint_reward", 0.0)

        print(f"\n  ╔═══════════════════════════════╗")
        print(f"  ║   QUANTUMPASS PASSPORT        ║")
        print(f"  ╠═══════════════════════════════╣")
        print(f"  ║  Identity   {self.identity:<19}║")
        print(f"  ║  Degrees    {self.get_degrees():<19.1f}║")
        print(f"  ║  Tier       {self.get_tier():<19}║")
        print(f"  ║  Blocks     {blocks:<19}║")
        print(f"  ║  Reward     {reward:<19.1f}║")
        print(f"  ╠═══════════════════════════════╣")
        print(f"  ║  AI Access                    ║")
        print(f"  ║  {self.get_ai_access():<31}║")
        print(f"  ╠═══════════════════════════════╣")
        print(f"  ║  Next Tier  {next_tier['name']:<19}║")
        print(f"  ║  Need       {next_tier['degrees_remaining']:<19.1f}║")
        print(f"  ╚═══════════════════════════════╝\n")

if __name__ == "__main__":
    passport = QuantumPassPassport("c-V-1J")
    passport.print_passport()