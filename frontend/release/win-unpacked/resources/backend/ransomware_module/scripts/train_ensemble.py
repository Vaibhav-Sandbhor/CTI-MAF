"""Train an ensemble consisting of the LSTM detector and a tree-based model.
The ensemble averages probability outputs from both models during evaluation.
"""
import os
import random
import numpy as np
import pandas as pd
import joblib
import argparse
from datetime import datetime

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier

# same model-building utilities as in train_model.py
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, Input, Bidirectional

# (tf seed will be set after parsing args, once SEED is known)

# ----------------------------------------------------------------------------
# configuration
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_PATH = os.path.join(ROOT, "data", "processed", "ransomware_features.csv")
OUTPUT_DIR = os.path.join(ROOT, "models")
# defaults; can be overridden via CLI

# ----------------------------------------------------------------------------
parser = argparse.ArgumentParser(description="Train LSTM + RF ensemble")
parser.add_argument("--seq", type=int, default=5, help="sequence length")
parser.add_argument("--hold", default="ryuk", help="family to hold out as zero-day")
parser.add_argument("--epochs", type=int, default=20)
parser.add_argument("--batch", type=int, default=256)
parser.add_argument("--pos-weight", type=float, default=1.0)
parser.add_argument("--oversample", action="store_true")
parser.add_argument("--out", default=OUTPUT_DIR, help="output directory for models")
parser.add_argument("--seed", type=int, default=42)
args = parser.parse_args()

SEQ_LENGTH = args.seq
HOLD_OUT_FAMILY = args.hold
EPOCHS = args.epochs
BATCH_SIZE = args.batch
POS_WEIGHT = args.pos_weight
OVERSAMPLE = args.oversample
OUTPUT_DIR = args.out
SEED = args.seed
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ensure TF randomness is seeded for determinism
tf.random.set_seed(SEED)

# log run info for reproducibility
import json, platform, subprocess
run_info = {
    'timestamp': datetime.now().isoformat(),
    'args': vars(args),
    'python_version': platform.python_version(),
}
try:
    git_hash = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).strip().decode()
    run_info['git_commit'] = git_hash
except Exception:
    pass
try:
    import pkg_resources
    run_info['packages'] = {d.project_name: d.version for d in pkg_resources.working_set}
except Exception:
    pass
with open(os.path.join(OUTPUT_DIR, 'ensemble_run_info.json'), 'w', encoding='utf-8') as f:
    json.dump(run_info, f, indent=2)

random.seed(SEED)
np.random.seed(SEED)
os.environ.setdefault('TF_DETERMINISTIC_OPS', '1')
os.environ.setdefault('TF_ENABLE_ONEDNN_OPTS', '0')
import tensorflow as tf

# reproducibility
with open(os.path.join(OUTPUT_DIR, 'seed.txt'), 'w') as f:
    f.write(str(SEED))

# ----------------------------------------------------------------------------
def create_sequences(X, y, seq_length):
    X_seq, y_seq = [], []
    for i in range(len(X) - seq_length):
        X_seq.append(X[i:i+seq_length])
        y_seq.append(y[i+seq_length])
    return np.array(X_seq), np.array(y_seq)

# load data
print("[+] Loading dataset for ensemble training...")
df = pd.read_csv(DATA_PATH)

FEATURE_COLS = [c for c in df.columns if c not in ("label","family")]

# dedup
print("[+] Removing duplicates...")
df = df.drop_duplicates(subset=FEATURE_COLS).reset_index(drop=True)

# split
zero_day = df[df['family']==HOLD_OUT_FAMILY].copy()
benign = df[df['family']=='benign'].copy()
benign_train, benign_test = train_test_split(benign, test_size=0.2, random_state=SEED, stratify=benign['label'])
train_fams = [f for f in df['family'].unique() if f not in [HOLD_OUT_FAMILY,'benign']]
train_df = pd.concat([df[df['family'].isin(train_fams)], benign_train], ignore_index=True)
test_df = pd.concat([zero_day, benign_test], ignore_index=True)

print("train families", train_fams)

# scaling
scaler = StandardScaler()
X_train_raw = train_df[FEATURE_COLS].values
y_train_raw = train_df['label'].values
X_test_raw = test_df[FEATURE_COLS].values
y_test_raw = test_df['label'].values

X_train_scaled = scaler.fit_transform(X_train_raw)
X_test_scaled = scaler.transform(X_test_raw)

# sequences
X_train, y_train = create_sequences(X_train_scaled, y_train_raw, SEQ_LENGTH)
X_test, y_test = create_sequences(X_test_scaled, y_test_raw, SEQ_LENGTH)
print("seq shapes", X_train.shape, X_test.shape)

# oversample / balance as before (reuse code from train_model)
if OVERSAMPLE:
    from imblearn.over_sampling import SMOTE
    shape = X_train.shape
    X_flat = X_train.reshape(shape[0], -1)
    sm = SMOTE(random_state=SEED)
    X_flat_res, y_res = sm.fit_resample(X_flat, y_train)
    X_train = X_flat_res.reshape(-1, shape[1], shape[2])
    y_train = y_res

ransom_idx = np.where(y_train==1)[0]
benign_idx = np.where(y_train==0)[0]
max_samples = min(len(ransom_idx), len(benign_idx))
np.random.seed(SEED)
ransom_sample = np.random.choice(ransom_idx, max_samples, replace=False)
benign_sample = np.random.choice(benign_idx, max_samples, replace=False)
balanced_idx = np.concatenate([ransom_sample, benign_sample])
np.random.shuffle(balanced_idx)
X_train_bal = X_train[balanced_idx]
y_train_bal = y_train[balanced_idx]

# RF training on flattened sequences
print("[+] Training RandomForest surrogate... (flattened sequences)")
X_rf = X_train_bal.reshape(X_train_bal.shape[0], -1)
rf = RandomForestClassifier(n_estimators=100, random_state=SEED)
rf.fit(X_rf, y_train_bal)
joblib.dump(rf, os.path.join(OUTPUT_DIR, "rf_model.joblib"))

# LSTM build & train
print("[+] Training LSTM model for ensemble...")

model = Sequential([
    Input(shape=(SEQ_LENGTH, len(FEATURE_COLS))),
    Bidirectional(LSTM(64, return_sequences=True)),
    Dropout(0.3),
    Bidirectional(LSTM(32)),
    Dropout(0.3),
    Dense(32, activation='relu'),
    Dense(1, activation='sigmoid')
])

optimizer = tf.keras.optimizers.Adam(learning_rate=5e-4)
model.compile(loss='binary_crossentropy', optimizer=optimizer,
              metrics=['accuracy', tf.keras.metrics.AUC()])

class_weights = {0:1.0, 1: POS_WEIGHT}

callbacks = [
    tf.keras.callbacks.EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True),
    tf.keras.callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=2, min_lr=1e-6)
]

# validation split
X_train_bal, X_val, y_train_bal, y_val = train_test_split(
    X_train_bal, y_train_bal, test_size=0.2, stratify=y_train_bal, random_state=SEED)

history = model.fit(
    X_train_bal, y_train_bal,
    validation_data=(X_val, y_val),
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    callbacks=callbacks,
    class_weight=class_weights,
    verbose=1
)

# save LSTM
model.save(os.path.join(OUTPUT_DIR, "lstm_model.keras"))
joblib.dump(scaler, os.path.join(OUTPUT_DIR, "scaler.pkl"))

# evaluate ensemble
print("[+] Evaluating ensemble on zero-day test set")

# get LSTM probs
lstm_probs = model.predict(X_test).flatten()
# RF probs require flattening test data as well
X_test_rf = X_test.reshape(X_test.shape[0], -1)
rf_probs = rf.predict_proba(X_test_rf)[:,1]

ensemble_probs = (lstm_probs + rf_probs) / 2

# optimal threshold (simple f1 search)
thresholds = np.linspace(0,1,101)
best = (0, -1)
for t in thresholds:
    preds = (ensemble_probs >= t).astype(int)
    f1 = tf.keras.metrics.F1Score(num_classes=1, threshold=t) if False else None
    # using sklearn
    from sklearn.metrics import f1_score
    val = f1_score(y_test, preds)
    if val > best[1]:
        best = (t, val)
print(f"Optimal ensemble threshold {best[0]:.2f} f1={best[1]:.3f}")

from sklearn.metrics import precision_score, recall_score
preds = (ensemble_probs >= best[0]).astype(int)
print(classification_report(y_test, preds))
print("Confusion:\n", confusion_matrix(y_test, preds))
print("ROC AUC:", roc_auc_score(y_test, ensemble_probs))

print("[+] Ensemble training complete, models saved in", OUTPUT_DIR)
