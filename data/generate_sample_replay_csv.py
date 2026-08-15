"""
Generates a demo CSV file shaped like a real exported network-flow log, so
you can see + demo replay mode immediately without hunting down a real
dataset first.

This is still synthetic under the hood (same distributions as simulator.py)
— it exists only to prove out the CSV replay pipeline end-to-end. For the
real hackathon story, swap the output path for an actual export: a CICIDS2017
/ NSL-KDD / UNSW-NB15 subset, or your own SIEM/flow-log CSV, resampled down
to these 5 columns:

    network_traffic_mbps, failed_logins, cpu_usage_pct, data_egress_mb,
    active_connections, attack_type (optional label column)

Run:
    python3 data/generate_sample_replay_csv.py
"""
import csv
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from simulator import METRIC_BASELINES, ATTACK_SIGNATURES, METRIC_NAMES  # noqa: E402

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
ROWS_PER_SECTOR = 500
ATTACK_BURST_PROBABILITY = 0.08


def generate_rows(n=ROWS_PER_SECTOR):
    rows = []
    cooldown, atype = 0, None
    for _ in range(n):
        if cooldown > 0:
            cooldown -= 1
        elif random.random() < ATTACK_BURST_PROBABILITY:
            cooldown = random.randint(2, 5)
            atype = random.choice(list(ATTACK_SIGNATURES))

        active = atype if cooldown > 0 or (cooldown == 0 and atype and random.random() < 0.3) else None
        row = {}
        for metric, (mean, std) in METRIC_BASELINES.items():
            value = max(0, random.gauss(mean, std))
            if active:
                lo, hi = ATTACK_SIGNATURES[active]["multipliers"][metric]
                value *= random.uniform(lo, hi)
            row[metric] = round(value, 2)
        row["attack_type"] = active or ""
        rows.append(row)
        if cooldown == 0:
            atype = None
    return rows


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=METRIC_NAMES + ["attack_type"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} rows -> {path}")


if __name__ == "__main__":
    for sector in ("hospital", "power_grid", "bank"):
        write_csv(os.path.join(OUT_DIR, f"{sector}_replay.csv"), generate_rows())