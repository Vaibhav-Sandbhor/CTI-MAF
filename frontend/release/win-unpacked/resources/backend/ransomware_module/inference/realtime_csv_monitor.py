"""
realtime_csv_monitor.py
========================
Module 4: Real-Time Monitoring Engine

Continuously tails data/live_input.csv for new rows, runs the LSTM detector
on each new behavioral event, and writes classified results to:

    output/predictions_log.csv
    output/alerts.log

Detection logic uses a two-layer defence:
    Layer 1 – Honeypot heuristic score  (always available)
    Layer 2 – LSTM probability          (available after model training)

A threat is escalated when EITHER layer fires above its threshold.

Output schema (predictions_log.csv):
    timestamp, process_name, prediction, confidence, threat_level, source

Alert levels:
    CRITICAL  – RANSOMWARE detected (confidence ≥ production threshold)
    WARNING   – SUSPICIOUS activity (confidence ≥ 0.50)
    INFO      – benign event (logged silently)

Usage:
    # Watch live_input.csv and run LSTM on every new row:
    python -m ransomware_module.inference.realtime_csv_monitor

    # With custom paths:
    python -m ransomware_module.inference.realtime_csv_monitor \\
        --input data/live_input.csv \\
        --pred-log output/predictions_log.csv \\
        --alerts  output/alerts.log \\
        --threshold 0.70 \\
        --poll 2.0
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_MODULE_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_INPUT     = _MODULE_ROOT / "data"   / "live_input.csv"
DEFAULT_PRED_LOG  = _MODULE_ROOT / "output" / "predictions_log.csv"
DEFAULT_ALERT_LOG = _MODULE_ROOT / "output" / "alerts.log"

PRED_HEADER = [
    "timestamp", "process_name", "prediction",
    "confidence", "threat_level", "source",
]

# ---------------------------------------------------------------------------
# Heuristic honeypot scoring (fallback when LSTM is unavailable)
# ---------------------------------------------------------------------------

def _heuristic_score(row: Dict) -> float:
    """
    Return [0,1] threat score from raw behavioral features without ML.
    Mirrors the ransomware_module heuristic engine.
    """
    score = 0.0
    try:
        entropy = float(row.get("entropy", 0) or 0)
        ext_ch  = int(row.get("extension_change", 0) or 0)
        writes  = int(row.get("file_write_count", 0) or 0)
        deletes = int(row.get("file_delete_count", 0) or 0)
        renames = int(row.get("registry_change_count", 0) or 0)
        cpu     = float(row.get("cpu_usage", 0) or 0)
    except (TypeError, ValueError):
        return 0.0

    if entropy > 7.0:    score += 0.35
    elif entropy > 6.0:  score += 0.20
    elif entropy > 4.5:  score += 0.08
    if ext_ch:           score += 0.25
    if writes > 20:      score += 0.20
    elif writes > 10:    score += 0.10
    elif writes > 5:     score += 0.05
    if deletes > 5:      score += 0.10
    elif deletes > 2:    score += 0.05
    if renames > 3:      score += 0.10
    if cpu > 70:         score += 0.10
    return round(min(score, 1.0), 4)


def _classify(score: float, threshold: float = 0.70) -> tuple:
    """Return (prediction, threat_level) from a probability score."""
    if score >= threshold:
        return "RANSOMWARE", "CRITICAL"
    if score >= 0.50:
        return "SUSPICIOUS", "WARNING"
    return "BENIGN", "INFO"


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

class PredictionLogger:
    """Thread-safe CSV + alert-log writer."""

    def __init__(
        self,
        pred_path:  Path = DEFAULT_PRED_LOG,
        alert_path: Path = DEFAULT_ALERT_LOG,
    ) -> None:
        self.pred_path  = pred_path
        self.alert_path = alert_path
        self._lock = threading.Lock()
        pred_path.parent.mkdir(parents=True, exist_ok=True)

        if not pred_path.exists():
            with open(pred_path, "w", newline="") as fh:
                csv.writer(fh).writerow(PRED_HEADER)

    def log_prediction(
        self,
        timestamp:    str,
        process_name: str,
        prediction:   str,
        confidence:   float,
        threat_level: str,
        source:       str,
    ) -> None:
        with self._lock:
            with open(self.pred_path, "a", newline="") as fh:
                csv.writer(fh).writerow([
                    timestamp, process_name, prediction,
                    round(confidence, 4), threat_level, source,
                ])
            if threat_level in ("CRITICAL", "WARNING"):
                self._write_alert(
                    timestamp, process_name, prediction, confidence, source
                )

    def _write_alert(
        self,
        timestamp:    str,
        process_name: str,
        prediction:   str,
        confidence:   float,
        source:       str,
    ) -> None:
        level_str = "CRITICAL ALERT" if prediction == "RANSOMWARE" else "WARNING ALERT"
        msg = (
            f"\n{'='*60}\n"
            f"{level_str}\n"
            f"Timestamp  : {timestamp}\n"
            f"Detection  : Early {prediction.lower()} detected\n"
            f"Process    : {process_name}\n"
            f"Confidence : {confidence:.4f}\n"
            f"Source     : {source}\n"
            f"{'='*60}\n"
        )
        with open(self.alert_path, "a") as fh:
            fh.write(msg)
        print(msg.strip())


# ---------------------------------------------------------------------------
# CSV tail reader
# ---------------------------------------------------------------------------

class CSVTailer:
    """
    Tails a CSV file and yields new rows as they are appended.
    Resumes from the last-seen position across calls to `poll()`.
    """

    def __init__(self, csv_path: Path) -> None:
        self.csv_path = csv_path
        self._offset  = 0       # byte offset after header
        self._header  = None
        self._initialized = False

    def _init(self) -> bool:
        if not self.csv_path.exists():
            return False
        with open(self.csv_path, "r", newline="") as fh:
            header_line = fh.readline()
            if not header_line:
                return False
            self._header = next(csv.reader([header_line]))
            # tell() works here because we used readline() not next()
            self._offset = fh.tell()
        self._initialized = True
        return True

    def poll(self) -> List[Dict]:
        """Return any new rows since last poll."""
        if not self._initialized:
            if not self._init():
                return []

        new_rows = []
        try:
            with open(self.csv_path, newline="") as fh:
                fh.seek(self._offset)
                reader = csv.DictReader(fh, fieldnames=self._header)
                for row in reader:
                    new_rows.append({k: (v.strip() if v else v) for k, v in row.items()})
                self._offset = fh.tell()
        except (OSError, IOError):
            pass
        return new_rows

    def reset(self) -> None:
        """Re-read from start (for testing)."""
        self._initialized = False
        self._offset = 0


# ---------------------------------------------------------------------------
# Monitor engine
# ---------------------------------------------------------------------------

class RealtimeCSVMonitor:
    """
    Core engine: tails live_input.csv, scores each row, writes outputs.

    Parameters
    ----------
    input_path     : path to live_input.csv
    pred_log_path  : path to predictions_log.csv
    alert_log_path : path to alerts.log
    threshold      : LSTM decision threshold (also used for heuristic)
    poll_interval  : seconds between file polls
    use_ml         : if True, attempt to load LSTM; else heuristic-only
    """

    def __init__(
        self,
        input_path:     Path  = DEFAULT_INPUT,
        pred_log_path:  Path  = DEFAULT_PRED_LOG,
        alert_log_path: Path  = DEFAULT_ALERT_LOG,
        threshold:      float = 0.70,
        poll_interval:  float = 2.0,
        use_ml:         bool  = True,
    ) -> None:
        self.threshold     = threshold
        self.poll_interval = poll_interval
        self.use_ml        = use_ml

        self._tailer  = CSVTailer(input_path)
        self._logger  = PredictionLogger(pred_log_path, alert_log_path)
        self._detector = None   # lazy-loaded
        self._ml_ready = False
        self._stats    = {"total": 0, "benign": 0, "suspicious": 0, "ransomware": 0}

        print(f"[MONITOR] Input         : {input_path}")
        print(f"[MONITOR] Predictions   : {pred_log_path}")
        print(f"[MONITOR] Alerts        : {alert_log_path}")
        print(f"[MONITOR] Threshold     : {threshold}")
        print(f"[MONITOR] ML enabled    : {use_ml}")

    # ------------------------------------------------------------------
    # Lazy ML loader
    # ------------------------------------------------------------------

    def _try_load_ml(self) -> bool:
        if not self.use_ml:
            return False
        try:
            from ransomware_module.models.predict_lstm import RansomwareDetector
            det = RansomwareDetector(threshold=self.threshold)
            det._ensure_loaded()   # trigger lazy load
            self._detector = det
            self._ml_ready = True
            print("[MONITOR] LSTM model loaded successfully.")
            return True
        except Exception as exc:
            print(f"[MONITOR] LSTM unavailable ({exc}) — using heuristic mode.")
            return False

    # ------------------------------------------------------------------
    # Row scoring
    # ------------------------------------------------------------------

    def _score_row(self, row: Dict) -> tuple:
        """
        Returns (confidence, prediction, threat_level, source).

        Tries LSTM first; falls back to heuristic.
        """
        # -- LSTM layer --------------------------------------------------
        if self._ml_ready and self._detector is not None:
            try:
                result = self._detector.predict_dict(row, source="HONEYPOT")
                return (
                    result["confidence"],
                    result["prediction"],
                    result["threat_level"],
                    "LSTM+HONEYPOT",
                )
            except Exception:
                pass

        # -- Heuristic fallback ------------------------------------------
        score = _heuristic_score(row)
        prediction, threat_level = _classify(score, self.threshold)
        return score, prediction, threat_level, "HONEYPOT_HEURISTIC"

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _process_row(self, row: Dict) -> None:
        ts   = row.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        proc = row.get("process_name", "unknown.exe")

        confidence, prediction, threat_level, source = self._score_row(row)

        self._logger.log_prediction(ts, proc, prediction, confidence, threat_level, source)
        self._stats["total"] += 1
        self._stats[prediction.lower()] += 1

        # Console output (non-alert events)
        if threat_level == "INFO":
            print(
                f"[MONITOR] {ts} | {proc:22s} | {prediction:10s} | "
                f"conf={confidence:.4f} | {source}"
            )

    def run(self, max_rows: Optional[int] = None) -> None:
        """
        Start monitoring loop. Blocks until Ctrl-C or *max_rows* processed.
        *max_rows* is useful for testing.
        """
        print(f"\n[MONITOR] Starting real-time monitor "
              f"(poll={self.poll_interval}s)…\n")

        # Attempt ML load once at startup
        self._try_load_ml()

        rows_processed = 0
        try:
            while True:
                new_rows = self._tailer.poll()
                for row in new_rows:
                    self._process_row(row)
                    rows_processed += 1
                    if max_rows and rows_processed >= max_rows:
                        raise KeyboardInterrupt

                if new_rows:
                    self._print_stats()

                time.sleep(self.poll_interval)

        except KeyboardInterrupt:
            print(f"\n[MONITOR] Stopped.  Processed {rows_processed} rows total.")
            self._print_stats(final=True)

    def _print_stats(self, final: bool = False) -> None:
        s = self._stats
        label = "Session summary" if final else "Running totals"
        print(
            f"[MONITOR] {label} — "
            f"total={s['total']}  benign={s['benign']}  "
            f"suspicious={s['suspicious']}  ransomware={s['ransomware']}"
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CyberSIEM Real-time CSV Ransomware Monitor")
    p.add_argument("--input",     type=Path, default=DEFAULT_INPUT,
                   help="path to live_input.csv")
    p.add_argument("--pred-log",  type=Path, default=DEFAULT_PRED_LOG,
                   help="output predictions_log.csv")
    p.add_argument("--alerts",    type=Path, default=DEFAULT_ALERT_LOG,
                   help="output alerts.log")
    p.add_argument("--threshold", type=float, default=0.70,
                   help="decision threshold (default: 0.70 production)")
    p.add_argument("--poll",      type=float, default=2.0,
                   help="poll interval seconds (default: 2.0)")
    p.add_argument("--no-ml",     action="store_true",
                   help="use heuristic-only mode (no LSTM)")
    p.add_argument("--max-rows",  type=int, default=None,
                   help="stop after N rows (testing mode)")
    return p


def main() -> None:
    args = _build_parser().parse_args()
    monitor = RealtimeCSVMonitor(
        input_path    =args.input,
        pred_log_path =args.pred_log,
        alert_log_path=args.alerts,
        threshold     =args.threshold,
        poll_interval =args.poll,
        use_ml        =not args.no_ml,
    )
    monitor.run(max_rows=args.max_rows)


if __name__ == "__main__":
    main()
