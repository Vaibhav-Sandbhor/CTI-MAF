"""
Train a RandomForest surrogate per LOFO fold to extract stable feature importances.
Saves CSV: evaluation_reports/feature_importance_lofo.csv
"""
import os
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_PATH = os.path.join(ROOT, "data", "processed", "ransomware_features.csv")
OUT_DIR = os.path.join(ROOT, "evaluation_reports")
os.makedirs(OUT_DIR, exist_ok=True)

SEQ_LENGTH = 5
RANDOM_STATE = 42

print("[+] Loading dataset...")
df = pd.read_csv(DATA_PATH)

# deduplicate on feature columns
FEATURE_COLS = [c for c in df.columns if c not in ("label", "family")]
df = df.drop_duplicates(subset=FEATURE_COLS).reset_index(drop=True)

# families and benign split (reuse same split logic)
families = sorted([f for f in df['family'].unique() if f != 'benign'])
benign_df = df[df['family'] == 'benign'].copy()
benign_train, benign_test = train_test_split(benign_df, test_size=0.2, random_state=RANDOM_STATE, stratify=benign_df['label'])

results = []

for held_out in families:
    print(f"\n[+] LOFO surrogate for held-out: {held_out}")
    # build train/test frames
    train_families = [f for f in families if f != held_out]
    train_ransom = df[df['family'].isin(train_families)].copy()
    train_df = pd.concat([train_ransom, benign_train], ignore_index=True)

    test_ransom = df[df['family'] == held_out].copy()
    test_df = pd.concat([test_ransom, benign_test], ignore_index=True)

    # prepare arrays
    X_train_raw = train_df[FEATURE_COLS].values
    y_train = train_df['label'].values
    X_test_raw = test_df[FEATURE_COLS].values
    y_test = test_df['label'].values

    # scale with training-only fit
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_raw)
    X_test_scaled = scaler.transform(X_test_raw)

    # create sequences
    def create_sequences(X, y, seq_length):
        Xs, ys = [], []
        for i in range(len(X) - seq_length):
            Xs.append(X[i:i+seq_length])
            ys.append(y[i+seq_length])
        return np.array(Xs), np.array(ys)

    X_train_seq, y_train_seq = create_sequences(X_train_scaled, y_train, SEQ_LENGTH)
    X_test_seq, y_test_seq = create_sequences(X_test_scaled, y_test, SEQ_LENGTH)

    # flatten sequences for tree-based surrogate
    n_samples, seq_len, n_features = X_train_seq.shape
    X_train_flat = X_train_seq.reshape(n_samples, seq_len * n_features)

    # train surrogate
    print("  Training RandomForest surrogate...")
    rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE, class_weight='balanced')
    rf.fit(X_train_flat, y_train_seq)

    # get importances and map back to original features by averaging across positions
    importances = rf.feature_importances_
    feat_imp = {}
    for feat_idx, feat_name in enumerate(FEATURE_COLS):
        vals = importances[feat_idx::n_features]
        feat_imp[feat_name] = float(np.mean(vals))

    sorted_imp = sorted(feat_imp.items(), key=lambda x: x[1], reverse=True)
    top5 = sorted_imp[:5]
    print("  Top 5 features:")
    for i, (name, imp) in enumerate(top5, 1):
        print(f"    {i}. {name}: {imp:.6f}")

    row = {'held_out_family': held_out}
    for i, (name, imp) in enumerate(top5, 1):
        row[f'top{i}'] = name
        row[f'top{i}_imp'] = imp

    results.append(row)

# save CSV
out_csv = os.path.join(OUT_DIR, f'feature_importance_lofo_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv')
pd.DataFrame(results).to_csv(out_csv, index=False)
print(f"\n[+] Saved surrogate importances to: {out_csv}")
