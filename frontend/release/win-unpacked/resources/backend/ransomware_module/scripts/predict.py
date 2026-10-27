import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
import os

# ---- Paths ----
MODEL_PATH = "ransomware_module/models/ransomware_lstm.keras"
FEATURE_COLUMNS = [
    "ata_write_ops",
    "ata_entropy_avg",
    "mem_write_ops",
    "mem_entropy_avg"
]

# ---- Function to predict a new sample ----
def predict_sample(sample_csv):
    if not os.path.exists(MODEL_PATH):
        print("[-] Model not found. Train first.")
        return

    if not os.path.exists(sample_csv):
        print(f"[-] Sample file not found: {sample_csv}")
        return

    # Load model
    model = load_model(MODEL_PATH)

    # Load sample features
    df = pd.read_csv(sample_csv)

    if df.empty:
        print("[-] Sample dataset is empty.")
        return

    X = df[FEATURE_COLUMNS].values
    # reshape to (samples, 1, features) for LSTM
    X = X.reshape((X.shape[0], 1, X.shape[1]))

    # Predict
    y_pred = (model.predict(X) > 0.5).astype(int).flatten()

    # Output alerts
    for i, pred in enumerate(y_pred):
        if pred == 1:
            print(f"[ALERT] Sample {i}: RANSOMWARE behavior detected")
        else:
            print(f"[INFO] Sample {i}: Benign behavior")

# ---- Run as script ----
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 predict.py <path_to_feature_csv>")
    else:
        predict_sample(sys.argv[1])
