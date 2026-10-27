"""Command‑line wrapper for the filesystem honeypot.

Example usage::

    python honeypot_manager.py \
        --path C:/Users/.../Documents \
        --decoys 10 \
        --window 10 \
        --threshold 0.7

This module initializes decoys, starts the filesystem monitor, and
periodically scores accumulated events.  Alerts are written to
logs/honeypot_events.jsonl in structured JSON format.
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

from .decoy_generator import DecoyGenerator
from .monitor import HoneypotMonitor, HoneypotEventHandler
from .scoring import ScoreConfig, evaluate


LOG_FILE = Path("logs") / "honeypot_events.jsonl"


def ensure_log_dir():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def log_event(record: dict):
    ensure_log_dir()
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Lightweight filesystem honeypot")
    parser.add_argument("--path", required=True, help="directory to monitor/create decoys in")
    parser.add_argument("--decoys", type=int, default=10, help="number of bait files to generate")
    parser.add_argument("--window", type=int, default=10, help="time window (seconds) for scoring")
    parser.add_argument("--threshold", type=float, default=0.7, help="suspicion threshold")
    args = parser.parse_args()

    base_dir = Path(args.path)
    generator = DecoyGenerator(base_dir, count=args.decoys)
    decoy_paths = generator.generate_decoys()

    handler = HoneypotEventHandler()
    monitor = HoneypotMonitor(str(base_dir), handler)
    monitor.start()
    config = ScoreConfig(threshold=args.threshold)

    print(f"[+] monitoring {base_dir} with {len(decoy_paths)} decoys")

    try:
        while True:
            time.sleep(args.window)
            events = handler.flush_events(args.window)
            modified = sum(1 for (_, t, _) in events if t == "modified")
            renamed = sum(1 for (_, t, _) in events if t == "renamed")
            # very basic write rate
            write_rate = modified / args.window if args.window > 0 else 0.0
            # entropy_delta requires reading before/after; stub zero
            entropy_delta = 0.0
            score, triggered = evaluate(
                modified, entropy_delta, renamed, write_rate, len(decoy_paths), config
            )
            record = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "event_count": len(events),
                "entropy_delta": entropy_delta,
                "rename_count": renamed,
                "write_rate": write_rate,
                "suspicion_score": score,
                "triggered": triggered,
            }
            print(json.dumps(record))
            log_event(record)

            if triggered:
                # optional ML integration
                try:
                    from models.predict_lstm import predict_dataframe, load_detector
                    import pandas as pd

                    df = pd.DataFrame([record])
                    model, scaler = load_detector()
                    probs, preds, thr_used = predict_dataframe(df, model, scaler)
                    print(f"[+] ML prediction: {probs.flatten()}, {preds}")
                except Exception:
                    pass
    except KeyboardInterrupt:
        monitor.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
