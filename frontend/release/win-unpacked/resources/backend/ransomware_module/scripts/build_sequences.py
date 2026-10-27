import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

PROCESSED_DIR = "ransomware_module/data/processed"
SEQUENCE_LENGTH = 5


def build_sequences():

    data_path = os.path.join(PROCESSED_DIR, "ransomware_features.csv")
    df = pd.read_csv(data_path)

    print("[+] Loaded dataset:", df.shape)

    feature_cols = [
        "ata_entropy_avg",
        "mem_entropy_avg",
        "disk_write_ratio",
        "mem_write_ratio"
    ]

    sequences = []
    labels = []

    # -------------------------------------------------
    # Build sequences PER SAMPLE (critical fix)
    # -------------------------------------------------
    for sample_id, group in df.groupby("sample_id"):

        group = group.sort_index()  # preserve order

        X = group[feature_cols].values
        y = group["label"].values

        if len(X) < SEQUENCE_LENGTH:
            continue

        # Normalize per sample (optional but cleaner)
        scaler = StandardScaler()
        X = scaler.fit_transform(X)

        for i in range(len(X) - SEQUENCE_LENGTH + 1):
            seq = X[i:i+SEQUENCE_LENGTH]
            label = y[i+SEQUENCE_LENGTH-1]

            sequences.append(seq)
            labels.append(label)

    X_seq = np.array(sequences)
    y_seq = np.array(labels)

    print("[+] Final Sequences shape:", X_seq.shape)
    print("[+] Sequence label distribution:")
    print(np.unique(y_seq, return_counts=True))

    # Save
    np.save(os.path.join(PROCESSED_DIR, "X_seq.npy"), X_seq)
    np.save(os.path.join(PROCESSED_DIR, "y_seq.npy"), y_seq)

    print("[+] Sequences saved successfully")


if __name__ == "__main__":
    build_sequences()
