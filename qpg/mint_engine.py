"""
mint_engine.py
QpG — QuantumPass Genesis
Surge equity mint engine
600,000,000 total supply
Halving + burn x6 on milestone surges
Every 360 degrees = one surge
2160 degrees = chain complete
"""

TOTAL_SUPPLY = 600_000_000
SURGE_INTERVAL = 360.0
CHAIN_MAX_DEGREES = 2160.0
TOTAL_SURGES = int(CHAIN_MAX_DEGREES / SURGE_INTERVAL)  # 6
BASE_MINT_REWARD = 10.0
BURN_RATE = 0.1

TIER_THRESHOLDS = [
    (2160.0, "PERFECT"),
    (1800.0, "SOVEREIGN"),
    (1440.0, "MASTER"),
    (1080.0, "JOURNEYMAN"),
    (720.0,  "INITIATE"),
    (360.0,  "APPRENTICE"),
    (0.0,    "SEED"),
]

def get_tier(cumulative_degrees: float) -> str:
    for threshold, label in TIER_THRESHOLDS:
        if cumulative_degrees >= threshold:
            return label
    return "SEED"

def calculate_mint_reward(block_num: int, total_60: float) -> float:
    halving_epoch = (block_num - 1) // 6
    reward = BASE_MINT_REWARD / (2 ** halving_epoch)
    return round(reward, 8)

def calculate_surge(surge_num: int, circulating: float) -> dict:
    burn_amount = circulating * BURN_RATE
    new_circulating = circulating - burn_amount
    return {
        "surge_number": surge_num,
        "burn_amount": round(burn_amount, 2),
        "circulating_after": round(new_circulating, 2),
        "supply_percent_burned": round((burn_amount / TOTAL_SUPPLY) * 100, 4)
    }

def process_block(block_num: int, total_60: float, cumulative_degrees: float, circulating: float) -> dict:
    reward = calculate_mint_reward(block_num, total_60)
    new_cumulative = cumulative_degrees
    surges = []

    surge_check = int(cumulative_degrees // SURGE_INTERVAL)
    if surge_check > 0 and cumulative_degrees % SURGE_INTERVAL == 0:
        surge = calculate_surge(surge_check, circulating)
        surges.append(surge)
        circulating = surge["circulating_after"]

    tier = get_tier(new_cumulative)

    return {
        "block": block_num,
        "mint_reward": reward,
        "cumulative_degrees": new_cumulative,
        "tier": tier,
        "surges_fired": surges,
        "circulating_supply": round(circulating + reward, 2),
        "chain_complete": new_cumulative >= CHAIN_MAX_DEGREES
    }

def print_mint_report(result: dict):
    print(f"\n  ═══════════════════════════════")
    print(f"  MINT ENGINE — BLOCK {result['block']}")
    print(f"  ═══════════════════════════════")
    print(f"  Reward       {result['mint_reward']}")
    print(f"  Degrees      {result['cumulative_degrees']}°")
    print(f"  Tier         {result['tier']}")
    print(f"  Circulating  {result['circulating_supply']:,}")
    if result['surges_fired']:
        for s in result['surges_fired']:
            print(f"  SURGE {s['surge_number']} FIRED — Burned {s['burn_amount']:,}")
    print(f"  Complete     {result['chain_complete']}")
    print(f"  ═══════════════════════════════\n")

if __name__ == "__main__":
    result = process_block(3, 56.0, 1032.0, 30.0)
    print_mint_report(result)