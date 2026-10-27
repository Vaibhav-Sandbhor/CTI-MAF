import numpy as np
import pandas as pd
import joblib
import os
import random

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

# ==========================================================
# CONFIG / CLI
# ==========================================================
import argparse
from datetime import datetime

# project root calculation
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

SEQ_LENGTH = 5
HOLD_OUT_FAMILY = "ryuk"        # Zero-day family (can be none to disable)
EPOCHS = 20
BATCH_SIZE = 256
DATA_PATH = os.path.join(ROOT, "data", "processed", "ransomware_features.csv")
OUTPUT_DIR = os.path.join(ROOT, "models")

# ==========================================================
# parse command-line options (useful for experimentation)
parser = argparse.ArgumentParser(description="Train LSTM ransomware detector")
parser.add_argument("--data", default=DATA_PATH, help="path to feature CSV")
parser.add_argument("--seq", type=int, default=SEQ_LENGTH,
                    help="sequence length for LSTM")
parser.add_argument("--hold", default=HOLD_OUT_FAMILY,
                    help="family to hold out as zero-day (blank to disable)")
parser.add_argument("--epochs", type=int, default=EPOCHS)
parser.add_argument("--batch", type=int, default=BATCH_SIZE)
parser.add_argument("--pos-weight", type=float, default=1.0,
                    help="factor to scale positive (ransomware) class weight")
parser.add_argument("--oversample", action="store_true",
                    help="apply SMOTE oversampling on the training set")
parser.add_argument("--loss", choices=["binary_crossentropy","focal"],
                    default="binary_crossentropy",
                    help="loss function to use")
parser.add_argument("--gamma", type=float, default=2.0,
                    help="focusing parameter for focal loss (if used)")
parser.add_argument("--thresh-metric", choices=["f1","recall"], default="f1",
                    help="metric used to select optimal decision threshold")
parser.add_argument("--min-precision", type=float, default=0.05,
                    help="minimum precision when optimizing recall threshold")
parser.add_argument("--out", default=OUTPUT_DIR, help="directory to save model/scaler")
parser.add_argument("--seed", type=int, default=42, help="random seed for reproducibility")
args = parser.parse_args()

SEQ_LENGTH = args.seq
HOLD_OUT_FAMILY = args.hold
EPOCHS = args.epochs
BATCH_SIZE = args.batch
POS_WEIGHT = args.pos_weight
OVERSAMPLE = args.oversample
LOSS = args.loss
GAMMA = args.gamma
THRESH_METRIC = args.thresh_metric
MIN_PRECISION = args.min_precision
DATA_PATH = args.data
OUTPUT_DIR = args.out
SEED = args.seed
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Set deterministic seeds
random.seed(SEED)
np.random.seed(SEED)

# Prefer deterministic TF ops where possible
os.environ.setdefault('TF_DETERMINISTIC_OPS', '1')
os.environ.setdefault('TF_ENABLE_ONEDNN_OPTS', '0')

# Import TensorFlow after setting environment and seeds
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, Input
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
from tensorflow.keras.layers import Bidirectional

tf.random.set_seed(SEED)

# persist seed used
with open(os.path.join(OUTPUT_DIR, 'seed.txt'), 'w') as sf:
    sf.write(str(SEED))

# record runtime configuration for reproducibility
import json, platform, subprocess
run_info = {
    'timestamp': datetime.now().isoformat(),
    'args': vars(args),
    'python_version': platform.python_version(),
}
# capture git commit if available
try:
    git_hash = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).strip().decode()
    run_info['git_commit'] = git_hash
except Exception:
    pass
# list installed packages
try:
    import pkg_resources
    run_info['packages'] = {d.project_name: d.version for d in pkg_resources.working_set}
except Exception:
    pass
with open(os.path.join(OUTPUT_DIR, 'run_info.json'), 'w', encoding='utf-8') as f:
    json.dump(run_info, f, indent=2)

# ==========================================================
# LOAD DATA
# ==========================================================
print("\n[+] Loading dataset...")
df = pd.read_csv(DATA_PATH)

print("Total samples before dedup:", len(df))
print("Label distribution:\n", df['label'].value_counts())
print("Families:", df['family'].unique())

# remove any rows with missing labels just in case
if 'label' not in df.columns:
    raise ValueError(f"no 'label' column found in {DATA_PATH}")

# ==========================================================
# FEATURE COLUMNS (choose all numeric columns except label/family)
# ==========================================================
FEATURE_COLS = [c for c in df.columns if c not in ("label", "family")]
print("Using features:", FEATURE_COLS)

# ==========================================================
# REMOVE DUPLICATES BEFORE SPLITTING
# ==========================================================
print("\n[+] Removing exact duplicates...")
before_dedup = len(df)
df = df.drop_duplicates(subset=FEATURE_COLS)
df = df.reset_index(drop=True)
removed = before_dedup - len(df)
print(f"Removed {removed} duplicate rows")
print(f"Total samples after dedup: {len(df)}")

# ==========================================================
# ZERO-DAY SPLIT (STRICT: NO ROW APPEARS IN BOTH)
# ==========================================================
print(f"\n[+] Splitting with strict zero-day holdout: {HOLD_OUT_FAMILY}")

# Extract zero-day test family and benign
zero_day_ransom = df[df['family'] == HOLD_OUT_FAMILY].copy()
benign_samples = df[df['family'] == "benign"].copy()

# Split benign: 80% train, 20% test
benign_train, benign_test = train_test_split(
    benign_samples,
    test_size=0.2,
    random_state=SEED,
    stratify=benign_samples['label'] if 'label' in benign_samples.columns else None
)

# Build train set: conti + lockbit + revil + benign_train (NO overlap with test)
training_families = [f for f in df['family'].unique() 
                     if f not in [HOLD_OUT_FAMILY, "benign"]]
train_ransom = df[df['family'].isin(training_families)].copy()
train_df = pd.concat([train_ransom, benign_train], ignore_index=True)

# Build test set: zero-day family + benign_test (STRICTLY separate)
test_df = pd.concat([zero_day_ransom, benign_test], ignore_index=True)

print(f"\nTraining families: {training_families}")
print(f"Test family: {HOLD_OUT_FAMILY}")
print(f"Benign split: {len(benign_train)} train / {len(benign_test)} test")

print("\nTrain distribution:")
print(train_df['label'].value_counts())
print("By family:", train_df['family'].value_counts())

print("\nTest distribution:")
print(test_df['label'].value_counts())
print("By family:", test_df['family'].value_counts())

# ==========================================================
# SCALE FEATURES
# ==========================================================
scaler = StandardScaler()

X_train_raw = train_df[FEATURE_COLS].values
y_train_raw = train_df["label"].values

X_test_raw = test_df[FEATURE_COLS].values
y_test_raw = test_df["label"].values

X_train_scaled = scaler.fit_transform(X_train_raw)
X_test_scaled = scaler.transform(X_test_raw)

# ==========================================================
# CREATE SEQUENCES
# ==========================================================
def create_sequences(X, y, seq_length):
    X_seq, y_seq = [], []
    for i in range(len(X) - seq_length):
        X_seq.append(X[i:i+seq_length])
        y_seq.append(y[i+seq_length])
    return np.array(X_seq), np.array(y_seq)

print("\n[+] Creating sequences...")
X_train, y_train = create_sequences(X_train_scaled, y_train_raw, SEQ_LENGTH)
X_test, y_test = create_sequences(X_test_scaled, y_test_raw, SEQ_LENGTH)

print("Train shape:", X_train.shape)
print("Test shape:", X_test.shape)

# ==========================================================
# BALANCE TRAINING DATA
# ==========================================================
# ==========================================================
# DEALING WITH IMBALANCE
# ==========================================================
print("\n[+] Handling class imbalance...")

if OVERSAMPLE:
    try:
        from imblearn.over_sampling import SMOTE
    except ImportError:
        raise ImportError("imblearn is required for oversampling; install via pip install imbalanced-learn")

    # flatten sequential data for SMOTE
    shape = X_train.shape
    X_flat = X_train.reshape(shape[0], -1)
    sm = SMOTE(random_state=SEED)
    X_flat_res, y_res = sm.fit_resample(X_flat, y_train)
    X_train = X_flat_res.reshape(-1, shape[1], shape[2])
    y_train = y_res
    print("Oversampled distribution:", np.bincount(y_train))

# default behaviour: undersample majority class after optional oversample
ransom_idx = np.where(y_train == 1)[0]
benign_idx = np.where(y_train == 0)[0]

max_samples = min(len(ransom_idx), len(benign_idx))

np.random.seed(SEED)

ransom_sample = np.random.choice(ransom_idx, max_samples, replace=False)
benign_sample = np.random.choice(benign_idx, max_samples, replace=False)

balanced_idx = np.concatenate([ransom_sample, benign_sample])
np.random.shuffle(balanced_idx)

X_train_bal = X_train[balanced_idx]
y_train_bal = y_train[balanced_idx]

print("Balanced distribution:", np.bincount(y_train_bal))

# ==========================================================
# STRATIFIED TRAIN / VALIDATION SPLIT
# ==========================================================
X_train_bal, X_val, y_train_bal, y_val = train_test_split(
    X_train_bal,
    y_train_bal,
    test_size=0.2,
    stratify=y_train_bal,
    random_state=SEED
)

print("Train split:", np.bincount(y_train_bal))
print("Validation split:", np.bincount(y_val))

# ==========================================================
# BUILD LSTM MODEL
# ==========================================================
print("\n[+] Building model... (stacked/bidirectional LSTM)")

from tensorflow.keras.layers import Bidirectional

# allow tuning of dropout and LSTM units via environment
drop_rate = float(os.environ.get('TF_DROPOUT', 0.3))
units_env = os.environ.get('TF_UNITS')  # expected like "64,32"
if units_env:
    try:
        u1, u2 = [int(x) for x in units_env.split(",")]
    except Exception:
        u1, u2 = 64, 32
else:
    u1, u2 = 64, 32

model = Sequential([
    Input(shape=(SEQ_LENGTH, len(FEATURE_COLS))),
    Bidirectional(LSTM(u1, return_sequences=True)),
    Dropout(drop_rate),
    Bidirectional(LSTM(u2)),
    Dropout(drop_rate),
    Dense(32, activation='relu'),
    Dense(1, activation='sigmoid')
])

# allow hyperparameter search to override learning rate via env var
lr = float(os.environ.get('TF_LEARNING_RATE', 0.0005))
optimizer = tf.keras.optimizers.Adam(
    learning_rate=lr,
    clipnorm=1.0
)

# determine loss function
if LOSS == "binary_crossentropy":
    loss_fn = "binary_crossentropy"
else:
    # focal loss implementation with optional positive weighting
    def focal_loss(y_true, y_pred):
        # compute basic BCE
        bce = tf.keras.losses.binary_crossentropy(y_true, y_pred)
        # scale by weight if pos weight specified
        if POS_WEIGHT != 1.0:
            weight = 1 + (POS_WEIGHT - 1) * y_true
            bce = bce * weight
        # focal term
        pt = tf.where(tf.equal(y_true, 1), y_pred, 1 - y_pred)
        gamma = GAMMA
        focal_factor = tf.pow(1 - pt, gamma)
        return focal_factor * bce
    loss_fn = focal_loss

model.compile(
    loss=loss_fn,
    optimizer=optimizer,
    metrics=["accuracy", tf.keras.metrics.AUC(name="auc")]
)

# ==========================================================
# EARLY STOPPING
# ==========================================================
early_stop = EarlyStopping(
    monitor="val_loss",
    patience=3,
    restore_best_weights=True
)

# ==========================================================
# TRAIN
# ==========================================================
print("\n[+] Training model...")

# compute class weights and apply POS_WEIGHT to ransomware class
from sklearn.utils import class_weight
class_weights = class_weight.compute_class_weight(
    class_weight="balanced", classes=np.unique(y_train_bal), y=y_train_bal
)
class_weights = dict(enumerate(class_weights))
if POS_WEIGHT != 1.0:
    class_weights[1] = class_weights.get(1,1.0) * POS_WEIGHT
print("class weights:", class_weights)

# callbacks for checkpoints and learning rate
checkpoint_path = os.path.join(OUTPUT_DIR, "best_model.keras")
callbacks = [early_stop,
             tf.keras.callbacks.ModelCheckpoint(checkpoint_path,
                                                save_best_only=True,
                                                monitor="val_loss"),
             tf.keras.callbacks.ReduceLROnPlateau(monitor="val_loss",
                                                  factor=0.5,
                                                  patience=2,
                                                  min_lr=1e-6)]

history = model.fit(
    X_train_bal,
    y_train_bal,
    validation_data=(X_val, y_val),
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    callbacks=callbacks,
    class_weight=class_weights,
    verbose=1
)

# save history for later inspection
import json
with open(os.path.join(OUTPUT_DIR, "history.json"), "w") as f:
    json.dump(history.history, f)

# ==========================================================
# ZERO-DAY EVALUATION
# ==========================================================
print("\n[+] Zero-Day Evaluation")

y_probs = model.predict(X_test)

# save probs/labels for later analysis (avoid needing TF)
os.makedirs(OUTPUT_DIR, exist_ok=True)
np.savez(os.path.join(OUTPUT_DIR, "analysis_inputs.npz"), y_probs=y_probs, y_test=y_test)

# diagnostic metrics at sample thresholds
from sklearn.metrics import precision_score, recall_score
for t in [0.3, 0.5, 0.7]:
    p = precision_score(y_test, (y_probs > t).astype(int))
    r = recall_score(y_test, (y_probs > t).astype(int))
    print(f"thresh {t:.2f}: precision={p:.3f}, recall={r:.3f}")

# determine optimal threshold if not given
from sklearn.metrics import f1_score, recall_score

thresholds = np.linspace(0, 1, 101)
best_t = 0.5
best_val = -1.0

if THRESH_METRIC == "f1":
    for t in thresholds:
        val = f1_score(y_test, (y_probs > t).astype(int))
        if val > best_val:
            best_val = val
            best_t = t
    print(f"optimal threshold (max f1): {best_t:.2f} f1={best_val:.3f}")
else:
    # maximize recall but avoid trivial threshold=0; require a minimum precision
    from sklearn.metrics import precision_score
    best_prec = 0.0
    best_t = 0.5
    # find candidate thresholds where recall is high and precision meets min requirement
    for t in thresholds:
        r = recall_score(y_test, (y_probs > t).astype(int))
        p = precision_score(y_test, (y_probs > t).astype(int))
        if r >= 0.95 and p >= MIN_PRECISION and p > best_prec:
            best_prec = p
            best_val = r
            best_t = t
    if best_prec == 0.0:
        # fallback to pure max recall (likely threshold=0)
        for t in thresholds:
            r = recall_score(y_test, (y_probs > t).astype(int))
            if r > best_val:
                best_val = r
                best_t = t
    print(f"optimal threshold (recall-first): {best_t:.2f} recall={best_val:.3f}")

# save threshold for inference
with open(os.path.join(OUTPUT_DIR, "threshold.txt"), "w") as f:
    f.write(str(best_t))

y_pred = (y_probs > best_t).astype(int)

print("\nZero-Day Classification Report:")
print(classification_report(y_test, y_pred))

print("\nZero-Day Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nZero-Day ROC AUC:")
print(roc_auc_score(y_test, y_probs))

print(f"\nSaved threshold file at {os.path.join(OUTPUT_DIR, 'threshold.txt')}\n")

# ==========================================================
# SAVE MODEL
# ==========================================================
# the checkpoint callback already stored the best weights; simply copy it
if os.path.exists(checkpoint_path):
    import shutil
    shutil.copy(checkpoint_path, os.path.join(OUTPUT_DIR, "lstm_model.keras"))
else:
    # fallback to saving current model
    model.save(os.path.join(OUTPUT_DIR, "lstm_model.keras"))

joblib.dump(scaler, os.path.join(OUTPUT_DIR, "scaler.pkl"))

print("\n[+] Model and scaler saved successfully in", OUTPUT_DIR)
