"""
block_value.py
QpG — QuantumPass Genesis
60-base hexagon scoring engine
6 faces x 10 = 60 max score
degrees / minutes / seconds output
"""

FACE_LABELS = [
    "Labor",
    "Exchange",
    "Equality",
    "Presence",
    "Ratification",
    "Continuity"
]

FACE_MAX = 10.0
TOTAL_MAX = 60.0
DEGREES_MAX = 360.0
CHAIN_MAX_DEGREES = 2160.0

GRADE_THRESHOLDS = [
    (60.0,  "PERFECT"),
    (54.0,  "SOVEREIGN"),
    (48.0,  "MASTER"),
    (42.0,  "JOURNEYMAN"),
    (36.0,  "INITIATE"),
    (24.0,  "APPRENTICE"),
    (0.0,   "SEED"),
]

HEXAGON = """
        ___
       /   \\
      / {0:^3} \\
     /         \\
    |   {1}   |
    |           |
     \\   {2}  /
      \\       /
       \\{3:^5}/
        ---
"""

def score_block(scores: dict) -> dict:
    total = sum(scores.values())
    degrees = (total / TOTAL_MAX) * DEGREES_MAX
    minutes = total
    seconds = total * 60.0
    percent = (total / TOTAL_MAX) * 100.0
    faces = total / FACE_MAX
    grade = get_grade(total)

    return {
        "scores": scores,
        "total_60": round(total, 4),
        "degrees": round(degrees, 4),
        "minutes": round(minutes, 4),
        "seconds": round(seconds, 4),
        "percent": round(percent, 4),
        "faces": round(faces, 4),
        "grade": grade
    }

def get_grade(total: float) -> str:
    for threshold, label in GRADE_THRESHOLDS:
        if total >= threshold:
            return label
    return "SEED"

def degrees_to_chain_progress(cumulative_degrees: float) -> dict:
    progress = (cumulative_degrees / CHAIN_MAX_DEGREES) * 100.0
    surges_fired = int(cumulative_degrees // DEGREES_MAX)
    return {
        "cumulative_degrees": cumulative_degrees,
        "chain_progress_percent": round(progress, 4),
        "surges_fired": surges_fired,
        "chain_complete": cumulative_degrees >= CHAIN_MAX_DEGREES
    }

def print_block_report(block_num: int, result: dict, cumulative: float):
    print(f"\n  ═══════════════════════════════")
    print(f"  BLOCK {block_num} — {result['grade']}")
    print(f"  ═══════════════════════════════")
    for face, score in result["scores"].items():
        bar = "█" * int(score)
        print(f"  {face:<15} {score:>4}  {bar}")
    print(f"  ───────────────────────────────")
    print(f"  Total        {result['total_60']:>6} / 60")
    print(f"  Degrees      {result['degrees']:>6}°")
    print(f"  Grade        {result['grade']}")
    chain = degrees_to_chain_progress(cumulative)
    print(f"  Chain        {chain['chain_progress_percent']}%")
    print(f"  Surges       {chain['surges_fired']}")
    print(f"  ═══════════════════════════════\n")

if __name__ == "__main__":
    test_scores = {
        "Labor": 10.0,
        "Exchange": 10.0,
        "Equality": 10.0,
        "Presence": 10.0,
        "Ratification": 10.0,
        "Continuity": 6.0
    }
    result = score_block(test_scores)
    print_block_report(3, result, 1032.0)