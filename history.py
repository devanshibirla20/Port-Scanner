"""
history.py — Lightweight scan history tracker using JSON persistence
"""

import json
import os
from datetime import datetime


HISTORY_FILE = "scan_history.json"
MAX_HISTORY = 20  


def _load() -> list[dict]:
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _save(records: list[dict]) -> None:
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(records[-MAX_HISTORY:], f, indent=2)
    except Exception:
        pass


def add_scan(target: str, ip: str, total_ports: int,
             open_count: int, high_risk: int, duration: float) -> None:
    records = _load()
    records.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "ip": ip,
        "total_ports": total_ports,
        "open_ports": open_count,
        "high_risk": high_risk,
        "duration": duration,
    })
    _save(records)


def get_history() -> list[dict]:
    return list(reversed(_load()))  # newest first


def clear_history() -> None:
    _save([])
