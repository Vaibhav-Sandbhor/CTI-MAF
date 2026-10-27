import os
import pandas as pd
import numpy as np

WINDOW_SIZE = 5
STEP_SIZE = 5


def extract_features(sample_path, label, family_name=None):

    # ===============================
    # BENIGN FILE CASE
    # ===============================
    if os.path.isfile(sample_path):

        df = pd.read_csv(sample_path)
        sample_id = os.path.basename(sample_path)

        if {"ata_entropy_avg", "mem_entropy_avg",
            "disk_write_ratio", "mem_write_ratio",
            "label"}.issubset(df.columns):

            df["sample_id"] = sample_id
            df["family"] = "benign"
            return df

        if "write_size" in df.columns:

            if len(df) < WINDOW_SIZE:
                return None

            rows = []

            for i in range(0, len(df) - WINDOW_SIZE + 1, STEP_SIZE):

                window = df.iloc[i:i+WINDOW_SIZE]

                rows.append({
                    "ata_entropy_avg": 0.0,
                    "mem_entropy_avg": 0.0,
                    "disk_write_ratio": window["write_size"].mean() / 4096,
                    "mem_write_ratio": 0.0,
                    "label": label,
                    "sample_id": sample_id,
                    "family": "benign"
                })

            return pd.DataFrame(rows)

        return None

    # ===============================
    # RANSOMWARE DIRECTORY CASE
    # ===============================
    ata_file = os.path.join(sample_path, "ata_write.csv")
    mem_file = os.path.join(sample_path, "mem_write.csv")

    if not os.path.exists(ata_file) or not os.path.exists(mem_file):
        return None

    ata = pd.read_csv(ata_file, header=None)
    mem = pd.read_csv(mem_file, header=None)

    ata.columns = ["sec", "ns", "lba", "size", "entropy", "_"]
    mem.columns = ["sec", "ns", "gpa", "size", "entropy", "type"]

    sample_id = os.path.basename(sample_path)

    min_len = min(len(ata), len(mem))

    if min_len < WINDOW_SIZE:
        return None

    rows = []

    for i in range(0, min_len - WINDOW_SIZE + 1, STEP_SIZE):

        ata_window = ata.iloc[i:i+WINDOW_SIZE]
        mem_window = mem.iloc[i:i+WINDOW_SIZE]

        rows.append({
            "ata_entropy_avg": ata_window["entropy"].mean(),
            "mem_entropy_avg": mem_window["entropy"].mean(),
            "disk_write_ratio": len(ata_window) / 1000,
            "mem_write_ratio": len(mem_window) / 1000,
            "label": label,
            "sample_id": sample_id,
            "family": family_name
        })

    return pd.DataFrame(rows)
