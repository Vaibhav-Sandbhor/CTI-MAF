import numpy as np
from tensorflow.keras.models import load_model

MODEL_PATH = "ransomware_module/models/ransomware_lstm.keras"
X_PATH = "ransomware_module/data/processed/X_sequences.npy"

model = load_model(MODEL_PATH)
X = np.load(X_PATH)

print("[*] Loaded trained ransomware detection model")

preds = model.predict(X)

for i, p in enumerate(preds):
    if p > 0.5:
        print(f"[ALERT] Sample {i}: RANSOMWARE behavior detected")
    else:
        print(f"[OK] Sample {i}: Benign behavior")
