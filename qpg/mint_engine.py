# mint_engine.py
# QpG Chain — Mint Engine
# 60-Base Math — Surge Equity — Halving — Burn ×6
# č̣V-1J — April 22, 2026
#
# 600,000,000 total supply
# Surge fires every 360° of cumulative hexagon degrees
# Six surges — six halvings — six burns — chain complete
# 2160° total = 6 full hexagons = cosmic completion

import json
import os
import math

# ════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════

TOTAL_SUPPLY        = 600_000_000
SURGE_DEGREES       = 360         # one full hexagon
TOTAL_SURGES        = 6           # six faces — six burns
TOTAL_DEGREES       = 2160        # 6 × 360° — chain complete
STARTING_REWARD     = 10.0        # mints per block at genesis
BURN_FACES          = 6           # burn multiplier — one per face

# Burn percentage per surge event
# Each burn takes a sixth of remaining unminted supply
BURN_RATE           = 1 / 6


# ════════════════════════════════════════
# SURGE SCHEDULE
# Build the full surge table at genesis
# ════════════════════════════════════════

def build_surge_schedule():
    """
    Calculate the full surge schedule.
    Returns list of 6 surge events with:
    - trigger degrees
    - reward at that surge
    - burn amount
    - cumulative minted
    - remaining supply
    """
    schedule   = []
    reward     = STARTING_REWARD
    minted     = 0
    remaining  = TOTAL_SUPPLY
    burned_total = 0

    for surge in range(1, TOTAL_SURGES + 1):
        trigger_degrees = surge * SURGE_DEGREES

        # Mints issued in this epoch
        # Each epoch runs until next surge
        # We calculate how many blocks at current reward
        # fill the epoch allocation
        epoch_allocation = TOTAL_SUPPLY / TOTAL_SURGES  # 100,000,000 per epoch

        # Burn amount — fraction of remaining supply
        burn_amount = round(remaining * BURN_RATE, 6)

        # After burn — remaining for this epoch
        epoch_after_burn = epoch_allocation - burn_amount

        schedule.append({
            "surge":            surge,
            "trigger_degrees":  trigger_degrees,
            "reward_per_block": round(reward, 8),
            "epoch_allocation": epoch_allocation,
            "burn_amount":      round(burn_amount, 6),
            "remaining_before": round(remaining, 6),
            "remaining_after":  round(remaining - burn_amount, 6),
            "face":             surge,
            "grade":            surge_grade(surge),
        })

        minted      += epoch_allocation
        burned_total += burn_amount
        remaining   -= (burn_amount)
        reward      /= 2  # halving

    return schedule


def surge_grade(surge_num):
    grades = {
        1: "⬡ INITIATE SURGE    — First Hexagon Complete",
        2: "⬡ APPRENTICE SURGE  — Two Hexagons Complete",
        3: "⬡ JOURNEYMAN SURGE  — Three Hexagons Complete",
        4: "⬡ SOVEREIGN SURGE   — Four Hexagons Complete",
        5: "⬡ MASTER SURGE      — Five Hexagons Complete",
        6: "⬡ PERFECT HEXAGON   — Chain Complete — 2160°",
    }
    return grades.get(surge_num, "⬡ UNKNOWN")


# ════════════════════════════════════════
# LIVE CHAIN STATE
# Where is the chain right now?
# ════════════════════════════════════════

def chain_state(results):
    """
    Given block value results — where is the chain?
    Returns current surge status, degrees, next milestone.
    """
    total_degrees = sum(r["degrees"] for r in results)
    total_60      = sum(r["total_60"] for r in results)
    num_blocks    = len(results)

    # Which surge are we in?
    surges_completed = int(total_degrees // SURGE_DEGREES)
    current_surge    = min(surges_completed + 1, TOTAL_SURGES)

    # Degrees into current surge
    degrees_into_surge = total_degrees % SURGE_DEGREES

    # Degrees to next surge
    degrees_to_next = SURGE_DEGREES - degrees_into_surge

    # Current reward
    current_reward = STARTING_REWARD / (2 ** surges_completed)

    # Progress through full chain
    chain_progress = (total_degrees / TOTAL_DEGREES) * 100

    # Mints issued so far (simplified)
    mints_issued = sum(
        (STARTING_REWARD / (2 ** min(int(r["degrees"] // SURGE_DEGREES), 5)))
        for r in results
    )

    return {
        "blocks":              num_blocks,
        "total_degrees":       round(total_degrees, 4),
        "total_60":            round(total_60, 4),
        "surges_completed":    surges_completed,
        "current_surge":       current_surge,
        "degrees_into_surge":  round(degrees_into_surge, 4),
        "degrees_to_next":     round(degrees_to_next, 4),
        "current_reward":      round(current_reward, 8),
        "chain_progress_pct":  round(chain_progress, 6),
        "mints_issued":        round(mints_issued, 6),
        "remaining_supply":    round(TOTAL_SUPPLY - mints_issued, 6),
    }


# ════════════════════════════════════════
# DETECT SURGE EVENT
# Did a new block trigger a surge?
# ════════════════════════════════════════

def detect_surge(prev_degrees, new_degrees):
    """
    Check if adding new block degrees crossed a 360° threshold.
    Returns surge number if triggered, else None.
    """
    prev_surges = int(prev_degrees // SURGE_DEGREES)
    new_surges  = int(new_degrees  // SURGE_DEGREES)

    if new_surges > prev_surges and new_surges <= TOTAL_SURGES:
        return new_surges
    return None


# ════════════════════════════════════════
# DISPLAY
# ════════════════════════════════════════

def display_surge_schedule(schedule):
    w = 64
    print(f"\n{'═'*w}")
    print(f"  QpG MINT ENGINE — SURGE SCHEDULE")
    print(f"  Total Supply : {TOTAL_SUPPLY:,}")
    print(f"  Total Surges : {TOTAL_SURGES}")
    print(f"  Total Degrees: {TOTAL_DEGREES}°  (6 × 360°)")
    print(f"{'─'*w}")
    print(f"  {'Surge':<6} {'Trigger':>8}° {'Reward':>12} {'Burn':>18} {'Remaining':>18}")
    print(f"{'─'*w}")

    for s in schedule:
        print(
            f"  {s['surge']:<6} "
            f"{s['trigger_degrees']:>8}°  "
            f"{s['reward_per_block']:>10.8f}  "
            f"{s['burn_amount']:>16,.2f}  "
            f"{s['remaining_after']:>16,.2f}"
        )

    print(f"{'─'*w}")
    for s in schedule:
        print(f"\n  Surge {s['surge']} — {s['grade']}")
    print(f"\n{'═'*w}\n")


def display_chain_state(state):
    w = 56
    print(f"\n{'═'*w}")
    print(f"  QpG CHAIN — LIVE STATE")
    print(f"{'─'*w}")
    print(f"  Blocks sealed      : {state['blocks']}")
    print(f"  Total degrees      : {state['total_degrees']}°")
    print(f"  Surges completed   : {state['surges_completed']} / 6")
    print(f"  Degrees into surge : {state['degrees_into_surge']}°")
    print(f"  Degrees to next    : {state['degrees_to_next']}°")
    print(f"  Current reward     : {state['current_reward']} mints/block")
    print(f"  Chain progress     : {state['chain_progress_pct']}%")
    print(f"  Mints issued       : {state['mints_issued']:,.6f}")
    print(f"  Remaining supply   : {state['remaining_supply']:,.6f}")

    # Progress bar — 60 chars wide
    filled = int((state['chain_progress_pct'] / 100) * 60)
    bar    = "█" * filled + "░" * (60 - filled)
    print(f"\n  [{bar}]")
    print(f"   0°{'':>26}2160°")
    print(f"   Genesis{'':>20}Chain Complete")
    print(f"{'═'*w}\n")


def display_surge_event(surge_num, schedule):
    s = schedule[surge_num - 1]
    w = 56
    print(f"\n{'═'*w}")
    print(f"  ⬡ SURGE EVENT TRIGGERED")
    print(f"  Surge           : {s['surge']} of 6")
    print(f"  Degrees crossed : {s['trigger_degrees']}°")
    print(f"  Grade           : {s['grade']}")
    print(f"{'─'*w}")
    print(f"  HALVING")
    print(f"  New reward      : {s['reward_per_block']} mints/block")
    print(f"{'─'*w}")
    print(f"  BURN ×{BURN_FACES}")
    print(f"  Burn amount     : {s['burn_amount']:,.6f} mints")
    print(f"  Remaining       : {s['remaining_after']:,.6f} mints")
    print(f"{'═'*w}\n")


# ════════════════════════════════════════
# WRITE MINT STATE TO CHAIN
# ════════════════════════════════════════

def write_mint_to_chain(chain, results, state, schedule):
    """Stamp mint state onto every block"""
    for i, block in enumerate(chain):
        block_degrees = results[i]["degrees"]
        surge_at_block = int(
            sum(r["degrees"] for r in results[:i+1]) // SURGE_DEGREES
        )
        reward = STARTING_REWARD / (2 ** min(surge_at_block, 5))

        block["mint"] = {
            "reward":           round(reward, 8),
            "degrees":          results[i]["degrees"],
            "surge_at_block":   surge_at_block,
            "chain_progress":   round(
                (sum(r["degrees"] for r in results[:i+1]) / TOTAL_DEGREES) * 100,
                6
            ),
        }
    return chain


# ════════════════════════════════════════
# MAIN
# ════════════════════════════════════════

def main():
    print(f"\n{'═'*56}")
    print(f"  QpG Chain — Mint Engine")
    print(f"  60-Base — Surge Equity — Halving — Burn ×6")
    print(f"  č̣V-1J — April 22, 2026")
    print(f"{'═'*56}")

    # Always show the full surge schedule first
    schedule = build_surge_schedule()
    display_surge_schedule(schedule)

    # Load chain
    candidates = [
        "quantumpass_č̣V-1J_chain.json",
        "quantumpass_V-1J_chain.json",
    ]
    chain_file = None
    for c in candidates:
        if os.path.exists(c):
            chain_file = c
            break

    if not chain_file:
        print("  No chain file found — showing schedule only.\n")
        return

    with open(chain_file, "r") as f:
        chain = json.load(f)

    # Load block values — need block_value module
    try:
        from block_value import calculate_chain_value
        results = calculate_chain_value(chain)
    except ImportError:
        print("  block_value.py not found.")
        print("  Run block_value.py first to calculate block scores.\n")
        return

    # Live chain state
    state = chain_state(results)
    display_chain_state(state)

    # Check for surge events in current chain
    cumulative = 0
    for i, r in enumerate(results):
        prev = cumulative
        cumulative += r["degrees"]
        surge = detect_surge(prev, cumulative)
        if surge:
            print(f"  Block {r['block']} triggered Surge {surge}!")
            display_surge_event(surge, schedule)

    # Write mint state to chain
    save = input("  Write mint scores into chain file? (yes/no): ").strip().lower()
    if save == "yes":
        chain = write_mint_to_chain(chain, results, state, schedule)
        with open(chain_file, "w") as f:
            json.dump(chain, f, indent=2)
        print(f"\n  Mint scores written to {chain_file}")
        print(f"  Every block now carries its mint value permanently.\n")


if __name__ == "__main__":
    main()