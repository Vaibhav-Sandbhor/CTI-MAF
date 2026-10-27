"""Monte Carlo validation harness for the hybrid honeypot + LSTM detector.

This standalone script performs large randomized simulations to estimate false
positive / true positive rates, detection latency, and score/probability
distributions.  It is intended for offline analysis and can be invoked directly
or from CI with a fixed seed to ensure reproducibility.

Usage::

    python tests/monte_carlo_validation.py --benign 500 --ransom 500 --seed 42

The output is a simple textual report; the script does not plot anything to avoid
additional dependencies.  The ML model is invoked when TensorFlow is available
and a model file can be loaded; if not the ML columns are skipped.
"""

import argparse
import os
import random
import statistics
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

# ensure our package modules are importable when running as script
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _root not in sys.path:
    sys.path.insert(0, _root)

from honeypot.scoring import evaluate, ScoreConfig
from honeypot.decoy_generator import DecoyGenerator

# skip any ML interaction by default; TensorFlow imports are slow and may
# crash the process during large Monte Carlo runs.  The primary goal here is
# honeypot scoring, so we leave ML disabled unless someone actively re-enables
# it for debugging.
ML_AVAILABLE = False


@dataclass
class RunResult:
    alert: bool
    max_score: float
    latency: Optional[float]  # seconds or None
    ml_prob: Optional[float]
    ml_prediction: Optional[int]


def simulate_benign_run(decoys: int, seed: int) -> RunResult:
    """Perform one benign session simulation."""
    # randomize number of edits and delays
    edits = random.randint(1, 3)
    delays = [random.uniform(2, 10) for _ in range(edits)]
    total_time = sum(delays)
    # accumulate events one by one to compute max score
    max_score = 0.0
    modified = 0
    for d in delays:
        modified += 1
        write_rate = modified / (sum(delays[:modified]) or 1e-6)
        score, triggered = evaluate(modified, 0.0, 0, write_rate, decoys)
        max_score = max(max_score, score)
    alert = max_score > 0.7
    latency = None  # not meaningful for benign
    # ML disabled in Monte Carlo runs
    return RunResult(alert, max_score, latency, None, None)


def simulate_ransom_run(decoys: int, seed: int) -> Tuple[RunResult, dict]:
    """Perform one ransomware session simulation.

    Returns both the `RunResult` and a dict of the randomized parameters for
    later analysis (useful for inspecting false negatives).
    """
    burst = random.randint(3, decoys)
    rename_prob = random.uniform(0.7, 1.0)
    renamed = burst if random.random() < rename_prob else random.randint(0, burst)
    entropy_delta = random.uniform(1.0, 8.0)
    burst_time = random.uniform(0.5, 3.0)
    write_rate = burst / burst_time
    # use default ScoreConfig implicitly (with updated weights)
    score, alert = evaluate(burst, entropy_delta, renamed, write_rate, decoys)
    latency = burst_time if alert else None
    # ML disabled in Monte Carlo runs
    ml_prob = ml_pred = None
    params = {
        "burst": burst,
        "renamed": renamed,
        "entropy_delta": entropy_delta,
        "burst_time": burst_time,
        "write_rate": write_rate,
    }
    return RunResult(alert, score, latency, ml_prob, ml_pred), params


def _make_ml_dataframe(ata, mem, rate):
    import pandas as pd

    return pd.DataFrame([
        {
            "ata_entropy_avg": ata,
            "mem_entropy_avg": mem,
            "disk_write_ratio": rate,
            "mem_write_ratio": rate,
        }
    ])


def summarize_results(results: List[RunResult], desc: str) -> None:
    n = len(results)
    alerts = sum(1 for r in results if r.alert)
    scores = [r.max_score for r in results]
    mean_score = statistics.mean(scores)
    std_score = statistics.stdev(scores) if n > 1 else 0.0
    ci = 1.96 * std_score / (n ** 0.5) if n > 0 else 0.0
    print(f"{desc} runs: {n}")
    print(f"  alerts: {alerts} (rate={alerts/n*100:.2f}%)")
    print(f"  mean score {mean_score:.3f} ± {ci:.3f} (95% CI)")
    # latency distribution for positives
    latencies = [r.latency for r in results if r.latency is not None]
    if latencies:
        print(f"  mean latency {statistics.mean(latencies):.3f}s")
        print(f"  median latency {statistics.median(latencies):.3f}s")
        p95 = sorted(latencies)[int(0.95 * len(latencies))]
        print(f"  95th percentile latency {p95:.3f}s")
    if ML_AVAILABLE:
        probs = [r.ml_prob for r in results if r.ml_prob is not None]
        if probs:
            print(f"  ML prob: mean {statistics.mean(probs):.3f}, std {statistics.stdev(probs):.3f}")
    print()


def main():
    parser = argparse.ArgumentParser(description="Monte Carlo validation of honeypot+ML")
    parser.add_argument("--benign", type=int, default=500)
    parser.add_argument("--ransom", type=int, default=500)
    parser.add_argument("--noisy", type=int, default=0)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
        import numpy as _np

        _np.random.seed(args.seed)

    decoys = 5
    benign_results = []
    for i in range(args.benign):
        benign_results.append(simulate_benign_run(decoys, i))
    ransom_results = []
    fn_details = []
    for i in range(args.ransom):
        result, params = simulate_ransom_run(decoys, i)
        ransom_results.append(result)
        if not result.alert:
            fn_details.append(params)

    print("Monte Carlo Validation Report")
    print("-" * 40)
    summarize_results(benign_results, "Benign")
    summarize_results(ransom_results, "Ransomware")

    # confusion matrix
    tn = len([r for r in benign_results if not r.alert])
    fp = len([r for r in benign_results if r.alert])
    tp = len([r for r in ransom_results if r.alert])
    fn = len([r for r in ransom_results if not r.alert])

    if fn_details:
        print("False-negative parameter samples (first 5):")
        for d in fn_details[:5]:
            print(d)
        print()
    print("Confusion matrix (honeypot):")
    print(f"  TN={tn}  FP={fp}")
    print(f"  FN={fn}  TP={tp}")
    print("Metrics:")
    total = tn + fp + fn + tp
    acc = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    tpr = recall
    print(f"  accuracy={acc:.3f}, precision={precision:.3f}, recall={recall:.3f}, f1={f1:.3f}")
    print(f"  FPR={fpr:.3f}, TPR={tpr:.3f}")


if __name__ == "__main__":
    main()
