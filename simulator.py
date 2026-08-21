"""
Simulates realistic telemetry for critical infrastructure sectors.
Occasionally injects labeled attack-like spikes so the detector has
something to catch AND classify.

Also supports "replay mode": instead of generating synthetic Gaussian
noise, a sector can be driven by a CSV file of real (or real-shaped)
telemetry readings, looping once it reaches the end. This is what lets
KAVACH run against real network-flow exports / SIEM extracts instead of
only fabricated data — see CsvReplaySource below.
"""
import csv
import os
import random

METRIC_BASELINES = {
    # metric: (mean, std) under normal conditions
    "network_traffic_mbps": (120, 15),
    "failed_logins": (2, 1.2),
    "cpu_usage_pct": (35, 8),
    "data_egress_mb": (5, 2),
    "active_connections": (150, 20),
}

METRIC_NAMES = list(METRIC_BASELINES.keys())

# Each attack type has its own distinctive metric "fingerprint" —
# this is what lets the detector classify *what kind* of attack it is,
# not just that something is wrong.
ATTACK_SIGNATURES = {
    "ddos": {
        "label": "DDoS / Volumetric Flood",
        "multipliers": {
            "network_traffic_mbps": (4.5, 8.0),
            "failed_logins": (1.0, 1.5),
            "cpu_usage_pct": (1.6, 2.2),
            "data_egress_mb": (1.2, 2.0),
            "active_connections": (4.0, 7.0),
        },
    },
    "bruteforce": {
        "label": "Brute-Force / Credential Stuffing",
        "multipliers": {
            "network_traffic_mbps": (1.2, 1.8),
            "failed_logins": (12.0, 30.0),
            "cpu_usage_pct": (1.2, 1.6),
            "data_egress_mb": (1.0, 1.4),
            "active_connections": (1.5, 2.2),
        },
    },
    "exfiltration": {
        "label": "Data Exfiltration",
        "multipliers": {
            "network_traffic_mbps": (1.8, 2.6),
            "failed_logins": (1.0, 1.8),
            "cpu_usage_pct": (1.1, 1.5),
            "data_egress_mb": (15.0, 45.0),
            "active_connections": (1.3, 1.8),
        },
    },
    "ransomware": {
        "label": "Ransomware / Encryption Activity",
        "multipliers": {
            "network_traffic_mbps": (1.3, 1.9),
            "failed_logins": (2.0, 4.0),
            "cpu_usage_pct": (2.2, 3.2),
            "data_egress_mb": (3.0, 7.0),
            "active_connections": (1.2, 1.6),
        },
    },
}

ATTACK_TYPES = list(ATTACK_SIGNATURES.keys())

# MITRE ATT&CK technique mapping for each classified attack type — lets the
# dashboard show "what we predicted" in the same vocabulary a SOC analyst
# (or an auditor) already thinks in, instead of just an internal label.
MITRE_MAPPING = {
    "ddos": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1498/",
    },
    "bruteforce": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
    "ransomware": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1486/",
    },
}


class CsvReplaySource:
    """Loops through a CSV of pre-recorded telemetry for one sector.

    Expected columns: the 5 metric names in METRIC_NAMES, plus an optional
    'attack_type' column (blank, or one of ATTACK_TYPES) if the rows are
    labeled. Unlabeled real-world exports work fine too — attack_type will
    just always come back None and the detector's own scoring does all the
    work, which is actually a more honest test of the model.
    """

    def __init__(self, csv_path):
        self.csv_path = csv_path
        self.rows = self._load(csv_path)
        if not self.rows:
            raise ValueError(f"No usable rows found in replay file: {csv_path}")
        self._i = 0

    def _load(self, csv_path):
        rows = []
        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)
            missing = [m for m in METRIC_NAMES if m not in reader.fieldnames]
            if missing:
                raise ValueError(
                    f"Replay file {csv_path} is missing required column(s): {missing}. "
                    f"Expected columns: {METRIC_NAMES + ['attack_type (optional)']}"
                )
            for row in reader:
                try:
                    reading = {m: float(row[m]) for m in METRIC_NAMES}
                except (TypeError, ValueError):
                    continue  # skip malformed rows rather than crash the loop
                atype = (row.get("attack_type") or "").strip() or None
                if atype not in (None, *ATTACK_TYPES):
                    atype = None
                rows.append((reading, atype))
        return rows

    def next_reading(self):
        reading, atype = self.rows[self._i]
        self._i = (self._i + 1) % len(self.rows)  # loop forever
        return dict(reading), atype


class TelemetrySimulator:
    def __init__(self, sectors, attack_probability=0.10, replay_files=None):
        """
        replay_files: optional {sector: csv_path}. Any sector present here
        is driven by CsvReplaySource.next_reading() instead of synthetic
        Gaussian generation. Sectors not in replay_files behave exactly as
        before (pure simulation).
        """
        self.sectors = sectors
        self.attack_probability = attack_probability
        self._attack_cooldown = {s: 0 for s in sectors}
        self._attack_type = {s: None for s in sectors}

        self.replay_sources = {}
        for sector, path in (replay_files or {}).items():
            if sector in sectors and path:
                self.replay_sources[sector] = CsvReplaySource(path)

    def is_replaying(self, sector):
        return sector in self.replay_sources

    def trigger_attack(self, sector, ticks=3, attack_type=None):
        """Manually force an attack-like reading for the next `ticks` calls.
        No-op for sectors in replay mode — their attack_type comes from the
        CSV, not from injection, so a manual trigger wouldn't do anything
        meaningful there."""
        if sector in self.replay_sources:
            return
        if sector in self._attack_cooldown:
            self._attack_cooldown[sector] = max(self._attack_cooldown[sector], ticks)
            self._attack_type[sector] = attack_type or random.choice(ATTACK_TYPES)

    def next_reading(self, sector):
        """Returns (reading: dict, attack_type: str|None)."""
        if sector in self.replay_sources:
            return self.replay_sources[sector].next_reading()

        reading = {}
        trigger_attack = False

        if self._attack_cooldown[sector] > 0:
            self._attack_cooldown[sector] -= 1
            trigger_attack = True
        elif random.random() < self.attack_probability:
            trigger_attack = True
            self._attack_cooldown[sector] = random.randint(1, 3)
            self._attack_type[sector] = random.choice(ATTACK_TYPES)

        active_type = self._attack_type[sector] if trigger_attack else None
        signature = ATTACK_SIGNATURES[active_type]["multipliers"] if active_type else None

        for metric, (mean, std) in METRIC_BASELINES.items():
            value = max(0, random.gauss(mean, std))
            if trigger_attack:
                lo, hi = signature[metric]
                value *= random.uniform(lo, hi)
            reading[metric] = round(value, 2)

        if not trigger_attack:
            self._attack_type[sector] = None

        return reading, active_type