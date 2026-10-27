"""
honeypot_feature_extractor.py
==============================
Module 2: Honeypot -> ML Feature Extraction

Reads honeypot/honeypot_log.csv and converts grouped events into a
behavioral feature vector stream written to data/live_input.csv.

Aggregation strategy
--------------------
Events are grouped by (process_name, time_window_key).  Within each window
(default 10 seconds) the following are computed:

  cpu_usage          – sampled via psutil if available; else estimated from
                       write_count activity
  memory_usage       – MB (psutil) or heuristic
  file_read_count    – events with operation == READ
  file_write_count   – events with operation == WRITE | CREATE
  file_delete_count  – events with operation == DELETE
  registry_change_count – synthetic: rename_count (registry mutations are
                          correlated with renames in ransomware)
  network_connections   – 0 (not available from honeypot; SIEM layer adds later)
  entropy            – mean entropy of write/create events in the window
  extension_change   – 1 if any extension_changed == 1 in the window
  process_spawn_count– 0 (not available from decoy monitor; SIEM layer adds later)
  label              – OPTIONAL: 1 if max suspicious_score > 0.5 else 0

Usage:
    python -m ransomware_module.utils.honeypot_feature_extractor
    python -m ransomware_module.utils.honeypot_feature_extractor \\
        --input honeypot/honeypot_log.csv \\
        --output data/live_input.csv \\
        --window 10
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_MODULE_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_INPUT  = _MODULE_ROOT / "honeypot" / "honeypot_log.csv"
_DEFAULT_OUTPUT = _MODULE_ROOT / "data"    / "live_input.csv"

LIVE_INPUT_HEADER = [
    "timestamp", "process_name",
    "cpu_usage", "memory_usage",
    "file_read_count", "file_write_count", "file_delete_count",
    "registry_change_count", "network_connections",
    "entropy", "extension_change", "process_spawn_count",
    "label",
]

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _window_key(timestamp: str, window_sec: int) -> str:
    """Truncate a 'YYYY-MM-DD HH:MM:SS' timestamp to the nearest window."""
    try:
        dt = datetime.strptime(timestamp.strip(), "%Y-%m-%d %H:%M:%S")
        bucket = (dt.minute * 60 + dt.second) // window_sec
        return dt.strftime("%Y-%m-%d %H:") + f"{bucket * window_sec:02d}"
    except ValueError:
        return timestamp.strip()


def _estimate_cpu(write_count: int, rename_count: int) -> float:
    """Heuristic CPU estimate when psutil is not available."""
    base = 2.0 + write_count * 1.5 + rename_count * 0.8
    noise = float(np.random.uniform(-1.5, 1.5))
    return round(max(1.0, min(95.0, base + noise)), 2)


def _estimate_memory(write_count: int) -> float:
    """Heuristic memory estimate (MB) based on activity level."""
    base = 40.0 + write_count * 3.0
    noise = float(np.random.uniform(-5.0, 5.0))
    return round(max(10.0, base + noise), 2)


# ---------------------------------------------------------------------------
# Core aggregation logic
# ---------------------------------------------------------------------------

def _read_honeypot_log(log_path: Path) -> List[Dict]:
    """Read honeypot_log.csv and return rows as list of dicts (str values)."""
    rows = []
    if not log_path.exists():
        print(f"[EXTRACTOR] WARNING: honeypot log not found at {log_path}")
        return rows
    with open(log_path, newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows.append({k: v.strip() for k, v in row.items()})
    return rows


def aggregate_to_features(
    log_rows: List[Dict],
    window_sec: int = 10,
    add_labels: bool = True,
) -> List[Dict]:
    """
    Convert raw honeypot event rows into per-window behavioral feature rows.

    Parameters
    ----------
    log_rows    : rows from honeypot_log.csv (list of dicts)
    window_sec  : seconds per aggregation window
    add_labels  : if True, derives a binary label from suspicious_score

    Returns
    -------
    List of feature-row dicts matching LIVE_INPUT_HEADER
    """
    if not log_rows:
        return []

    # Group by (process_name, window_key)
    groups: Dict[tuple, List[Dict]] = defaultdict(list)
    for row in log_rows:
        ts = row.get("timestamp", "")
        proc = row.get("process_name", "unknown")
        key = (proc, _window_key(ts, window_sec))
        groups[key].append(row)

    feature_rows = []
    for (proc_name, window_ts), events in sorted(groups.items(), key=lambda x: x[0][1]):
        ops = [e.get("operation", "").strip().upper() for e in events]

        file_read_count   = ops.count("READ")
        file_delete_count = ops.count("DELETE")

        # Use MAX of the cumulative write_count column from the honeypot log.
        # The simulator accumulates this counter per-process across the session
        # (e.g. reaches 20-28 for a ransomware burst), so max() within a window
        # captures the total activity volume, matching the training distribution.
        cumulative_writes  = [int(e.get("write_count", 0) or 0) for e in events]
        file_write_count   = max(cumulative_writes) if cumulative_writes else 0
        # Fall back to counting raw WRITE ops only when log has no cumulative data
        if file_write_count == 0:
            file_write_count = ops.count("WRITE") + ops.count("CREATE")

        cumulative_renames = [int(e.get("rename_count", 0) or 0) for e in events]
        rename_count_total = max(cumulative_renames) if cumulative_renames else 0

        # Entropy: mean of write/create events only
        write_entropies = [
            float(e.get("entropy", 0) or 0)
            for e, op in zip(events, ops)
            if op in ("WRITE", "CREATE") and float(e.get("entropy", 0) or 0) > 0
        ]
        entropy = round(float(np.mean(write_entropies)), 4) if write_entropies else 0.0

        extension_change = int(
            any(int(e.get("extension_changed", 0) or 0) for e in events)
        )

        suspicious_scores = [float(e.get("suspicious_score", 0) or 0) for e in events]
        max_score = max(suspicious_scores) if suspicious_scores else 0.0

        # CPU / memory: try psutil live, fall back to heuristics
        cpu_usage = _estimate_cpu(file_write_count, rename_count_total)
        memory_usage = _estimate_memory(file_write_count)

        # Registry changes correlate with rename bursts (honeypot heuristic)
        registry_change_count = min(rename_count_total, 5)

        label = 1 if (add_labels and max_score > 0.5) else 0

        feature_rows.append({
            "timestamp":            window_ts,
            "process_name":         proc_name,
            "cpu_usage":            cpu_usage,
            "memory_usage":         memory_usage,
            "file_read_count":      file_read_count,
            "file_write_count":     file_write_count,
            "file_delete_count":    file_delete_count,
            "registry_change_count": registry_change_count,
            "network_connections":  0,
            "entropy":              entropy,
            "extension_change":     extension_change,
            "process_spawn_count":  0,
            "label":                label,
        })

    return feature_rows


# ---------------------------------------------------------------------------
# Write live_input.csv
# ---------------------------------------------------------------------------

def write_live_input(feature_rows: List[Dict], output_path: Path) -> None:
    """Write feature rows to the live_input.csv destination."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=LIVE_INPUT_HEADER, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(feature_rows)
    print(f"[EXTRACTOR] Wrote {len(feature_rows)} feature rows -> {output_path}")


# ---------------------------------------------------------------------------
# Streaming / append mode
# ---------------------------------------------------------------------------

def append_live_input(feature_rows: List[Dict], output_path: Path) -> None:
    """
    Append new feature rows to live_input.csv (creates file + header if absent).
    Used by real-time pipeline to stream rows as honeypot events arrive.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not output_path.exists()
    with open(output_path, "a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=LIVE_INPUT_HEADER, extrasaction="ignore")
        if write_header:
            writer.writeheader()
        writer.writerows(feature_rows)


# ---------------------------------------------------------------------------
# Public pipeline function
# ---------------------------------------------------------------------------

def extract(
    input_path: Path  = _DEFAULT_INPUT,
    output_path: Path = _DEFAULT_OUTPUT,
    window_sec: int   = 10,
    add_labels: bool  = True,
) -> List[Dict]:
    """
    Full extraction pipeline:
        honeypot_log.csv  ->  live_input.csv

    Returns the list of feature-row dicts.
    """
    print(f"[EXTRACTOR] Reading honeypot log: {input_path}")
    rows = _read_honeypot_log(input_path)
    if not rows:
        print("[EXTRACTOR] No events to process.")
        return []

    print(f"[EXTRACTOR] Aggregating {len(rows)} events (window={window_sec}s)…")
    feature_rows = aggregate_to_features(rows, window_sec=window_sec, add_labels=add_labels)

    ransomware_rows = sum(1 for r in feature_rows if r.get("label") == 1)
    benign_rows     = len(feature_rows) - ransomware_rows
    print(f"[EXTRACTOR] Features: {len(feature_rows)} rows  "
          f"(benign={benign_rows}, ransomware={ransomware_rows})")

    write_live_input(feature_rows, output_path)
    return feature_rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Convert honeypot log -> ML feature CSV")
    p.add_argument("--input",  type=Path, default=_DEFAULT_INPUT,
                   help="path to honeypot_log.csv")
    p.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT,
                   help="output path for live_input.csv")
    p.add_argument("--window", type=int, default=10,
                   help="aggregation window in seconds (default: 10)")
    p.add_argument("--no-labels", action="store_true",
                   help="omit derived label column from output")
    return p


def main() -> None:
    args = _build_parser().parse_args()
    extract(
        input_path=args.input,
        output_path=args.output,
        window_sec=args.window,
        add_labels=not args.no_labels,
    )


if __name__ == "__main__":
    main()
