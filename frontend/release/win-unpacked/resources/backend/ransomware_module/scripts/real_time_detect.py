import os
import sys
import argparse
from collections import deque

import numpy as np
import joblib
from tensorflow.keras.models import load_model

# assume input lines are comma-separated numeric features matching training data order
# example usage:
#   tail -f new_windows.csv | python scripts/real_time_detect.py --seq 5

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_PATH = os.path.join(ROOT, "models", "lstm_model.keras")
SCALER_PATH = os.path.join(ROOT, "models", "scaler.pkl")
THRESH_PATH = os.path.join(ROOT, "models", "threshold.txt")

parser = argparse.ArgumentParser(description="Realtime ransomware detector")
parser.add_argument("--seq", type=int, default=5,
                    help="sequence length for LSTM window")
parser.add_argument("--threshold", type=float, default=None,
                    help="override the decision threshold")
parser.add_argument("--mode", choices=["balanced","high","low"],
                    help="predefined mode for threshold selection")
parser.add_argument("--verbose", action="store_true",
                    help="print every prediction")
args = parser.parse_args()

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"model not found at {MODEL_PATH}")

model = load_model(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

threshold = args.threshold
if threshold is None:
    if args.mode:
        # predetermined values; ideally load from file
        map_modes = {"balanced": 0.11, "high": 0.05, "low": 0.7}
        threshold = map_modes.get(args.mode, 0.11)
    elif os.path.exists(THRESH_PATH):
        try:
            threshold = float(open(THRESH_PATH).read().strip())
        except Exception:
            threshold = 0.5
if threshold is None:
    threshold = 0.5

buf = deque(maxlen=args.seq)

print(f"Realtime detector started (seq={args.seq}, threshold={threshold})")
print("waiting for comma-separated feature vectors on stdin...")

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        values = np.fromstring(line, sep=",")
    except ValueError:
        continue
    if values.size == 0:
        continue
    buf.append(values)
    if len(buf) < args.seq:
        continue
    arr = np.vstack(buf)
    # transform
    arr_scaled = scaler.transform(arr)
    arr_scaled = arr_scaled.reshape((1, args.seq, arr_scaled.shape[1]))
    prob = model.predict(arr_scaled, verbose=0)[0,0]
    pred = 1 if prob > threshold else 0
    if args.verbose or pred == 1:
        tag = "RANSOM" if pred == 1 else "benign"
        print(f"{tag} {prob:.4f}")
    # flush output to allow tailing
    sys.stdout.flush()
