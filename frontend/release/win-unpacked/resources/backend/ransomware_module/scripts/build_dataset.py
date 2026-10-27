import os
import pandas as pd
import numpy as np
from scipy.stats import entropy

import argparse

# compute project root (one level up from this script)
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BASE_PATH = os.path.join(ROOT, "data", "raw")
OUTPUT_PATH = os.path.join(ROOT, "data", "processed", "ransomware_features.csv")

# default parameters; can be overridden on the command line
WINDOW_SIZE = 50
STEP_SIZE = 50  # non‑overlapping by default
VALUE_COLUMN = 2  # index of the column in ata/mem csv to use for features (0-based)



def calculate_entropy(series):
    value_counts = series.value_counts(normalize=True)
    return entropy(value_counts)

def max_consecutive_writes(series):
    max_count = count = 0
    for val in series:
        if val > 0:
            count += 1
            max_count = max(max_count, count)
        else:
            count = 0
    return max_count

def process_trace(trace_path, family_name, label,
                  window_size, step_size, value_column):
    """Extract features from a single trace folder.

    The CSV files have several columns; ``value_column`` selects which one to
    treat as the signal (e.g. bytes written).  Windows are taken with a
    configurable ``step_size`` which lets you overlap them if desired.
    """

    ata_path = os.path.join(trace_path, "ata_write.csv")
    mem_path = os.path.join(trace_path, "mem_write.csv")

    if not os.path.exists(ata_path) or not os.path.exists(mem_path):
        return []

    ata_df = pd.read_csv(ata_path)
    mem_df = pd.read_csv(mem_path)

    # pick the column we will actually use; fall back gracefully if index is
    # out‑of‑range.
    def select_series(df):
        if value_column < df.shape[1]:
            return df.iloc[:, value_column]
        # last column if requested index is invalid
        return df.iloc[:, -1]

    if len(ata_df) < window_size or len(mem_df) < window_size:
        return []

    min_len = min(len(ata_df), len(mem_df))
    ata_series = select_series(ata_df.iloc[:min_len])
    mem_series = select_series(mem_df.iloc[:min_len])

    features = []

    for start in range(0, min_len - window_size + 1, step_size):
        ata_window = ata_series.iloc[start:start + window_size]
        mem_window = mem_series.iloc[start:start + window_size]

        # compute additional engineered features
        ata_pctiles = np.percentile(ata_window, [25, 50, 75])
        mem_pctiles = np.percentile(mem_window, [25, 50, 75])
        # simple FFT energy (sum of squared magnitudes, drop zero-frequency)
        def fft_energy(series):
            vals = np.asarray(series)
            if len(vals) == 0:
                return 0.0
            fft = np.fft.fft(vals)
            mag = np.abs(fft)
            # exclude DC term at index 0
            return np.sum(mag[1:]**2)

        feature_dict = {
            "family": family_name,
            "label": label,

            # Original features
            "ata_entropy_avg": calculate_entropy(ata_window),
            "mem_entropy_avg": calculate_entropy(mem_window),
            "disk_write_ratio": np.mean(ata_window > 0),
            "mem_write_ratio": np.mean(mem_window > 0),

            # Basic statistics
            "ata_variance": np.var(ata_window),
            "mem_variance": np.var(mem_window),

            # delta and totals
            "disk_write_delta_mean": np.mean(np.abs(np.diff(ata_window))),
            "mem_write_delta_mean": np.mean(np.abs(np.diff(mem_window))),
            "total_disk_writes": np.sum(ata_window),
            "total_mem_writes": np.sum(mem_window),
            "max_consecutive_disk_writes": max_consecutive_writes(ata_window),
            "max_consecutive_mem_writes": max_consecutive_writes(mem_window),

            # percentiles
            "ata_p25": ata_pctiles[0],
            "ata_p50": ata_pctiles[1],
            "ata_p75": ata_pctiles[2],
            "mem_p25": mem_pctiles[0],
            "mem_p50": mem_pctiles[1],
            "mem_p75": mem_pctiles[2],

            # FFT energy
            "ata_fft_energy": fft_energy(ata_window),
            "mem_fft_energy": fft_energy(mem_window),
        }

        features.append(feature_dict)

    return features


def build_dataset(window_size, step_size, value_column, base_path,
                  output_path):
    all_features = []

    for root, dirs, files in os.walk(base_path):
        if "ata_write.csv" in files and "mem_write.csv" in files:
            path_parts = root.split(os.sep)
            if "Benign" in path_parts or "benign" in path_parts:
                label = 0
                family = "benign"
            else:
                label = 1
                family = path_parts[-2]

            print(f"Processing trace: {root}")
            features = process_trace(root, family, label,
                                     window_size, step_size, value_column)
            if not features:
                print("  skipped (too short or missing data)")
            all_features.extend(features)

    df = pd.DataFrame(all_features)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)

    print("\nDataset built successfully.")
    print("Total samples:", len(df))
    if not df.empty and "label" in df.columns:
        print(df['label'].value_counts())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build a windowed feature dataset from raw traces"
    )
    parser.add_argument("--base", default=BASE_PATH,
                        help="root of raw traces")
    parser.add_argument("--output", default=OUTPUT_PATH,
                        help="where to write the CSV")
    parser.add_argument("--window", type=int, default=WINDOW_SIZE,
                        help="window size in rows")
    parser.add_argument("--step", type=int, default=STEP_SIZE,
                        help="step between windows (allows overlap)")
    parser.add_argument("--column", type=int, default=VALUE_COLUMN,
                        help="value column index to extract from CSVs")
    args = parser.parse_args()

    build_dataset(args.window, args.step, args.column, args.base, args.output)