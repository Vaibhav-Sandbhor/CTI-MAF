"""
Data Drift Detection System
- Monitors distribution changes in new vs historical data
- Detects drift in: open_ports_count, avg_cvss, service_count
- Alerts when drift exceeds threshold
- Requires minimum new samples before triggering drift
"""

import os
import pandas as pd
import numpy as np
from datetime import datetime
from scipy import stats

# ────────────────────────────────
# CONFIGURATION
# ────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")

HISTORICAL_DATASET = os.path.join(DATA_DIR, "dataset.csv")
NEW_SCAN_LOGS = os.path.join(DATA_DIR, "new_scan_logs.csv")
DRIFT_LOG = os.path.join(LOGS_DIR, "drift_detection.log")

if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

DRIFT_THRESHOLD = 20  # percent
MIN_NEW_SAMPLES_FOR_DRIFT = 50

MONITORED_FEATURES = ["open_ports_count", "avg_cvss", "service_count"]

# ────────────────────────────────
# LOGGING
# ────────────────────────────────
def log_drift_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] {message}"

    with open(DRIFT_LOG, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")

    print(log_msg)

# ────────────────────────────────
# DATA LOADING
# ────────────────────────────────
def load_datasets():
    try:
        if not os.path.exists(HISTORICAL_DATASET):
            log_drift_event("⚠️  Historical dataset not found.")
            return None, None

        if not os.path.exists(NEW_SCAN_LOGS):
            log_drift_event("⚠️  New scan logs not found.")
            return None, None

        historical_df = pd.read_csv(HISTORICAL_DATASET, usecols=["open_ports_count", "avg_cvss", "service_count"])
        new_df = pd.read_csv(NEW_SCAN_LOGS, usecols=["open_ports_count", "avg_cvss", "service_count"], on_bad_lines="skip")

        log_drift_event(f"✅ Loaded {len(historical_df)} historical samples")
        log_drift_event(f"✅ Loaded {len(new_df)} new scan samples")

        return historical_df, new_df

    except Exception as e:
        log_drift_event(f"❌ Error loading datasets: {str(e)}")
        return None, None

# ────────────────────────────────
# STATISTICS
# ────────────────────────────────
def calculate_distribution_stats(df, feature):
    if feature not in df.columns:
        return None

    data = df[feature].dropna()
    if len(data) == 0:
        return None

    return {
        "mean": data.mean(),
        "std": data.std(),
        "median": data.median(),
        "count": len(data)
    }

def calculate_drift_percentage(hist_stats, new_stats):
    if hist_stats is None or new_stats is None:
        return 0

    mean_diff = abs(hist_stats["mean"] - new_stats["mean"]) / (abs(hist_stats["mean"]) + 1e-10) * 100
    median_diff = abs(hist_stats["median"] - new_stats["median"]) / (abs(hist_stats["median"]) + 1e-10) * 100
    std_diff = abs(hist_stats["std"] - new_stats["std"]) / (abs(hist_stats["std"]) + 1e-10) * 100

    return (mean_diff + median_diff + std_diff) / 3

def perform_statistical_test(hist_data, new_data):
    try:
        hist_vals = hist_data.dropna()
        new_vals = new_data.dropna()

        if len(hist_vals) == 0 or len(new_vals) == 0:
            return False, 1.0

        statistic, p_value = stats.ks_2samp(hist_vals, new_vals)
        return p_value < 0.05, p_value

    except Exception as e:
        log_drift_event(f"❌ Statistical test error: {str(e)}")
        return False, 1.0

# ────────────────────────────────
# DRIFT DETECTION
# ────────────────────────────────
def detect_drift():

    log_drift_event("\n" + "="*70)
    log_drift_event("📊 DATA DRIFT DETECTION STARTED")
    log_drift_event("="*70)

    historical_df, new_df = load_datasets()

    if historical_df is None or new_df is None:
        log_drift_event("❌ Cannot perform drift detection.")
        return False

    drift_detected = False
    drift_summary = []

    for feature in MONITORED_FEATURES:

        log_drift_event(f"\n🔍 Analyzing feature: {feature}")
        log_drift_event("─" * 50)

        hist_stats = calculate_distribution_stats(historical_df, feature)
        new_stats = calculate_distribution_stats(new_df, feature)

        if hist_stats is None or new_stats is None:
            log_drift_event(f"⚠️  Insufficient data for {feature}")
            continue

        drift_percent = calculate_drift_percentage(hist_stats, new_stats)

        log_drift_event("Historical Distribution:")
        log_drift_event(f"  Mean: {hist_stats['mean']:.2f}, Std: {hist_stats['std']:.2f}, Median: {hist_stats['median']:.2f}")
        log_drift_event("New Distribution:")
        log_drift_event(f"  Mean: {new_stats['mean']:.2f}, Std: {new_stats['std']:.2f}, Median: {new_stats['median']:.2f}")
        log_drift_event(f"Drift: {drift_percent:.2f}%")

        is_different, p_value = perform_statistical_test(
            historical_df[feature],
            new_df[feature]
        )

        log_drift_event(f"KS-Test p-value: {p_value:.4f}")

        # 🟡 Small sample protection
        if len(new_df) < MIN_NEW_SAMPLES_FOR_DRIFT:
            status = "INSUFFICIENT_DATA"
            log_drift_event(
                f"🟡 INSUFFICIENT DATA - Only {len(new_df)} samples "
                f"(minimum {MIN_NEW_SAMPLES_FOR_DRIFT} required)"
            )

        elif drift_percent > DRIFT_THRESHOLD and is_different:
            drift_detected = True
            status = "DRIFT"
            log_drift_event(
                f"🔴 DRIFT DETECTED - Exceeds {DRIFT_THRESHOLD}% "
                f"AND statistically significant"
            )

        else:
            status = "STABLE"
            log_drift_event("🟢 STABLE - Within acceptable range")

        drift_summary.append({
            "feature": feature,
            "drift": drift_percent,
            "status": status
        })

    # ────────────────────────────────
    # SUMMARY
    # ────────────────────────────────
    log_drift_event("\n" + "="*70)
    log_drift_event("📋 DRIFT DETECTION SUMMARY:")
    log_drift_event("="*70)

    for item in drift_summary:
        if item["status"] == "DRIFT":
            emoji = "🔴"
        elif item["status"] == "INSUFFICIENT_DATA":
            emoji = "🟡"
        else:
            emoji = "🟢"

        log_drift_event(
            f"{emoji} {item['feature']:20s} "
            f"Drift: {item['drift']:6.2f}% [{item['status']}]"
        )

    if drift_detected:
        log_drift_event("\n⚠️  DATA DRIFT DETECTED!")
        log_drift_event("🔄 RECOMMENDATION: Consider retraining if sufficient samples available.")
    else:
        log_drift_event("\n✅ NO CRITICAL DRIFT DETECTED")

    log_drift_event("="*70 + "\n")

    return drift_detected

# ────────────────────────────────
# MAIN
# ────────────────────────────────
if __name__ == "__main__":
    drift_detected = detect_drift()
    exit(1 if drift_detected else 0)