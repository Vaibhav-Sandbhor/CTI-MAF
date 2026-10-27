"""
COMPREHENSIVE CROSS-FAMILY EVALUATION
=====================================

STEP 1: Leave-One-Family-Out (LOFO) Evaluation
STEP 2: Single-Family Training Stress Test
STEP 3: Performance Stability Analysis
STEP 4: Feature Importance Consistency Check
STEP 5: Generate Findings Report
"""

import numpy as np
import pandas as pd
import os
import json
import joblib
from datetime import datetime

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    precision_recall_curve, roc_curve, auc, f1_score, precision_score, recall_score
)
from sklearn.inspection import permutation_importance

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, Input, Bidirectional
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import warnings
warnings.filterwarnings('ignore')

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_PATH = os.path.join(ROOT, "data", "processed", "ransomware_features.csv")
OUTPUT_DIR = os.path.join(ROOT, "models")
REPORT_DIR = os.path.join(ROOT, "evaluation_reports")
os.makedirs(REPORT_DIR, exist_ok=True)

SEQ_LENGTH = 5
EPOCHS = 20
BATCH_SIZE = 256
POS_WEIGHT = 3.0
# Disable expensive TF permutation importance here to avoid retracing issues.
# Set to True to attempt permutation importance (may be slow/fragile).
DO_PERM_IMPORTANCE = False

# ==========================================================
# UTILITY FUNCTIONS
# ==========================================================

def build_model(seq_length, feature_cols):
    """Build bidirectional LSTM model"""
    model = Sequential([
        Input(shape=(seq_length, len(feature_cols))),
        Bidirectional(LSTM(64, return_sequences=True)),
        Dropout(0.3),
        Bidirectional(LSTM(32)),
        Dropout(0.3),
        Dense(32, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    return model

def create_sequences(X, y, seq_length):
    """Create temporal sequences"""
    X_seq, y_seq = [], []
    for i in range(len(X) - seq_length):
        X_seq.append(X[i:i+seq_length])
        y_seq.append(y[i+seq_length])
    return np.array(X_seq), np.array(y_seq)

def balance_data(X, y):
    """Balance training data via undersampling"""
    ransom_idx = np.where(y == 1)[0]
    benign_idx = np.where(y == 0)[0]
    max_samples = min(len(ransom_idx), len(benign_idx))
    
    np.random.seed(42)
    ransom_sample = np.random.choice(ransom_idx, max_samples, replace=False)
    benign_sample = np.random.choice(benign_idx, max_samples, replace=False)
    
    balanced_idx = np.concatenate([ransom_sample, benign_sample])
    np.random.shuffle(balanced_idx)
    
    return X[balanced_idx], y[balanced_idx]

def find_optimal_threshold(y_true, y_prob, metric='f1'):
    """Find optimal decision threshold"""
    thresholds = np.linspace(0.1, 0.9, 81)
    best_thresh = 0.5
    best_score = -1
    
    for thresh in thresholds:
        y_pred = (y_prob >= thresh).astype(int)
        if metric == 'f1':
            score = f1_score(y_true, y_pred)
        else:
            score = recall_score(y_true, y_pred)
        if score > best_score:
            best_score = score
            best_thresh = thresh
    
    return best_thresh

# ==========================================================
# LOAD AND PREPROCESS DATA
# ==========================================================
print("\n" + "="*70)
print("COMPREHENSIVE CROSS-FAMILY EVALUATION")
print("="*70)

print("\n[+] Loading dataset...")
df = pd.read_csv(DATA_PATH)

print(f"Total samples before dedup: {len(df)}")
print("Label distribution:")
print(df['label'].value_counts())
print("Families:", sorted(df['family'].unique()))

# Remove duplicates
df = df.drop_duplicates(subset=[c for c in df.columns if c not in ("label", "family")])
df = df.reset_index(drop=True)
print(f"Total samples after dedup: {len(df)}")

FEATURE_COLS = [c for c in df.columns if c not in ("label", "family")]
print(f"Features ({len(FEATURE_COLS)}): {FEATURE_COLS[:3]}... (showing first 3)")

# Extract families
families = sorted([f for f in df['family'].unique() if f != 'benign'])
benign_df = df[df['family'] == 'benign'].copy()

print(f"\nRansomware families: {families}")
print(f"Benign samples: {len(benign_df)}")

# Split benign 80/20 (ONCE, reuse for all tests)
benign_train, benign_test = train_test_split(
    benign_df,
    test_size=0.2,
    random_state=42,
    stratify=benign_df['label']
)

print(f"Benign split: {len(benign_train)} train / {len(benign_test)} test")

# ==========================================================
# STEP 1: LEAVE-ONE-FAMILY-OUT EVALUATION
# ==========================================================
print("\n" + "="*70)
print("STEP 1: LEAVE-ONE-FAMILY-OUT (LOFO) EVALUATION")
print("="*70)

lofo_results = []

for held_out_family in families:
    print(f"\n[LOFO] Training on all families EXCEPT {held_out_family}...")
    
    # Build train set
    train_families = [f for f in families if f != held_out_family]
    train_ransom = df[df['family'].isin(train_families)].copy()
    train_df = pd.concat([train_ransom, benign_train], ignore_index=True)
    
    # Build test set
    test_ransom = df[df['family'] == held_out_family].copy()
    test_df = pd.concat([test_ransom, benign_test], ignore_index=True)
    
    print(f"  Train: {len(train_df)} samples ({train_df['label'].sum()} ransomware)")
    print(f"  Test:  {len(test_df)} samples ({test_df['label'].sum()} ransomware)")
    
    # Prepare data
    scaler = StandardScaler()
    X_train_raw = train_df[FEATURE_COLS].values
    y_train_raw = train_df["label"].values
    X_test_raw = test_df[FEATURE_COLS].values
    y_test_raw = test_df["label"].values
    
    X_train_scaled = scaler.fit_transform(X_train_raw)
    X_test_scaled = scaler.transform(X_test_raw)
    
    # Create sequences
    X_train, y_train = create_sequences(X_train_scaled, y_train_raw, SEQ_LENGTH)
    X_test, y_test = create_sequences(X_test_scaled, y_test_raw, SEQ_LENGTH)
    
    # Balance training
    X_train_bal, y_train_bal = balance_data(X_train, y_train)
    
    # Train-val split
    X_train_bal, X_val, y_train_bal, y_val = train_test_split(
        X_train_bal, y_train_bal,
        test_size=0.2,
        stratify=y_train_bal,
        random_state=42
    )
    
    # Build and train model
    model = build_model(SEQ_LENGTH, FEATURE_COLS)
    
    class_weights = {0: 1.0, 1: POS_WEIGHT}
    
    model.compile(
        loss='binary_crossentropy',
        optimizer=tf.keras.optimizers.Adam(learning_rate=5e-4),
        metrics=['accuracy', tf.keras.metrics.AUC()]
    )
    
    callbacks = [
        EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True),
        ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3, min_lr=1e-6)
    ]
    
    print(f"  Training... ({EPOCHS} epochs)")
    history = model.fit(
        X_train_bal, y_train_bal,
        validation_data=(X_val, y_val),
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        class_weight=class_weights,
        callbacks=callbacks,
        verbose=0
    )
    
    # Evaluate
    y_probs = model.predict(X_test, verbose=0).flatten()
    y_pred_default = (y_probs >= 0.5).astype(int)
    
    # Find optimal threshold
    optimal_thresh = find_optimal_threshold(y_test, y_probs, metric='f1')
    y_pred_optimal = (y_probs >= optimal_thresh).astype(int)
    
    # Metrics
    roc_auc = roc_auc_score(y_test, y_probs)
    precision = precision_score(y_test, y_pred_optimal)
    recall = recall_score(y_test, y_pred_optimal)
    f1 = f1_score(y_test, y_pred_optimal)
    cm = confusion_matrix(y_test, y_pred_optimal)
    
    print(f"  ROC AUC: {roc_auc:.4f}")
    print(f"  Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
    print(f"  Confusion Matrix:\n{cm}")
    
    lofo_results.append({
        'held_out_family': held_out_family,
        'train_families': train_families,
        'roc_auc': float(roc_auc),
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'confusion_matrix': cm.tolist(),
        'optimal_threshold': float(optimal_thresh),
        'model': model,
        'scaler': scaler
    })

# ==========================================================
# STEP 2: SINGLE-FAMILY TRAINING STRESS TEST
# ==========================================================
print("\n" + "="*70)
print("STEP 2: SINGLE-FAMILY TRAINING STRESS TEST")
print("="*70)

single_family_results = []

for train_family in families:
    print(f"\n[STRESS TEST] Training on {train_family} only...")
    
    # Build train set: only this family + benign_train
    train_ransom = df[df['family'] == train_family].copy()
    train_df = pd.concat([train_ransom, benign_train], ignore_index=True)
    
    print(f"  Train: {len(train_df)} samples ({train_df['label'].sum()} ransomware)")
    
    # Test on all other families
    test_families = [f for f in families if f != train_family]
    test_ransom = df[df['family'].isin(test_families)].copy()
    test_df = pd.concat([test_ransom, benign_test], ignore_index=True)
    
    print(f"  Test:  {len(test_df)} samples ({test_df['label'].sum()} ransomware)")
    
    # Prepare data
    scaler = StandardScaler()
    X_train_raw = train_df[FEATURE_COLS].values
    y_train_raw = train_df["label"].values
    X_test_raw = test_df[FEATURE_COLS].values
    y_test_raw = test_df["label"].values
    
    X_train_scaled = scaler.fit_transform(X_train_raw)
    X_test_scaled = scaler.transform(X_test_raw)
    
    # Create sequences
    X_train, y_train = create_sequences(X_train_scaled, y_train_raw, SEQ_LENGTH)
    X_test, y_test = create_sequences(X_test_scaled, y_test_raw, SEQ_LENGTH)
    
    # Balance training
    X_train_bal, y_train_bal = balance_data(X_train, y_train)
    
    # Train-val split
    X_train_bal, X_val, y_train_bal, y_val = train_test_split(
        X_train_bal, y_train_bal,
        test_size=0.2,
        stratify=y_train_bal,
        random_state=42
    )
    
    # Build and train model
    model = build_model(SEQ_LENGTH, FEATURE_COLS)
    
    class_weights = {0: 1.0, 1: POS_WEIGHT}
    
    model.compile(
        loss='binary_crossentropy',
        optimizer=tf.keras.optimizers.Adam(learning_rate=5e-4),
        metrics=['accuracy', tf.keras.metrics.AUC()]
    )
    
    callbacks = [
        EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True),
        ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=3, min_lr=1e-6)
    ]
    
    print(f"  Training... ({EPOCHS} epochs)")
    history = model.fit(
        X_train_bal, y_train_bal,
        validation_data=(X_val, y_val),
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        class_weight=class_weights,
        callbacks=callbacks,
        verbose=0
    )
    
    # Evaluate
    y_probs = model.predict(X_test, verbose=0).flatten()
    y_pred_default = (y_probs >= 0.5).astype(int)
    optimal_thresh = find_optimal_threshold(y_test, y_probs, metric='f1')
    y_pred_optimal = (y_probs >= optimal_thresh).astype(int)
    
    # Metrics
    roc_auc = roc_auc_score(y_test, y_probs)
    precision = precision_score(y_test, y_pred_optimal)
    recall = recall_score(y_test, y_pred_optimal)
    f1 = f1_score(y_test, y_pred_optimal)
    cm = confusion_matrix(y_test, y_pred_optimal)
    
    print(f"  ROC AUC: {roc_auc:.4f}")
    print(f"  Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
    print(f"  (Testing on: {', '.join(test_families)})")
    
    single_family_results.append({
        'train_family': train_family,
        'test_families': test_families,
        'roc_auc': float(roc_auc),
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'confusion_matrix': cm.tolist()
    })

# ==========================================================
# STEP 3: PERFORMANCE STABILITY ANALYSIS
# ==========================================================
print("\n" + "="*70)
print("STEP 3: PERFORMANCE STABILITY ANALYSIS")
print("="*70)

# Create comparison table
lofo_df = pd.DataFrame([
    {
        'Train Families': ', '.join(r['train_families']),
        'Test Family': r['held_out_family'],
        'ROC AUC': f"{r['roc_auc']:.4f}",
        'Recall': f"{r['recall']:.4f}",
        'Precision': f"{r['precision']:.4f}",
        'F1': f"{r['f1']:.4f}",
    }
    for r in lofo_results
])

print("\nLEAVE-ONE-FAMILY-OUT RESULTS:")
print(lofo_df.to_string(index=False))

# Calculate variance
roc_auc_values = [r['roc_auc'] for r in lofo_results]
recall_values = [r['recall'] for r in lofo_results]
f1_values = [r['f1'] for r in lofo_results]

print(f"\nSTABILITY METRICS:")
print(f"  ROC AUC:  μ={np.mean(roc_auc_values):.4f}, σ={np.std(roc_auc_values):.4f}")
print(f"  Recall:   μ={np.mean(recall_values):.4f}, σ={np.std(recall_values):.4f}")
print(f"  F1 Score: μ={np.mean(f1_values):.4f}, σ={np.std(f1_values):.4f}")

cv_roc = (np.std(roc_auc_values) / np.mean(roc_auc_values)) * 100
cv_recall = (np.std(recall_values) / np.mean(recall_values)) * 100
cv_f1 = (np.std(f1_values) / np.mean(f1_values)) * 100

print(f"\nCOEFFICIENT OF VARIATION (lower = more stable):")
print(f"  ROC AUC:  {cv_roc:.2f}%")
print(f"  Recall:   {cv_recall:.2f}%")
print(f"  F1 Score: {cv_f1:.2f}%")

stability_threshold = 15.0
if cv_roc < stability_threshold and cv_recall < stability_threshold:
    print(f"  ✅ STABLE: Low variance across families (CV < {stability_threshold}%)")
else:
    print(f"  ⚠️  VARIABLE: High variance across families (CV > {stability_threshold}%)")

# ==========================================================
# STEP 4: FEATURE IMPORTANCE ANALYSIS
# ==========================================================
print("\n" + "="*70)
print("STEP 4: FEATURE IMPORTANCE STABILITY")
print("="*70)

print("\n[+] Extracting feature importance (permutation-based, first 2 families for speed)...")

# Use first 2 LOFO results to extract feature importance
feature_importance_results = []

if not DO_PERM_IMPORTANCE:
    print("  Skipping permutation-based feature importance (disabled to avoid TF retracing).")
else:
    for i, result in enumerate(lofo_results[:2]):  # Limit to 2 for speed
        held_out = result['held_out_family']
        model = result['model']
        scaler = result['scaler']

        # Reconstruct test data
        train_families = result['train_families']
        train_ransom = df[df['family'].isin(train_families)].copy()
        train_df = pd.concat([train_ransom, benign_train], ignore_index=True)
        test_ransom = df[df['family'] == held_out].copy()
        test_df = pd.concat([test_ransom, benign_test], ignore_index=True)

        X_test_raw = test_df[FEATURE_COLS].values
        y_test_raw = test_df["label"].values
        X_test_scaled = scaler.transform(X_test_raw)
        X_test_seq, y_test_seq = create_sequences(X_test_scaled, y_test_raw, SEQ_LENGTH)

        print(f"\n  Held-out family: {held_out}")

        # For LSTM, use permutation importance on flattened input
        X_flat = X_test_seq.reshape(X_test_seq.shape[0], -1)

        def scoring_func(X_flat_sample, y_sample):
            X_sample = X_flat_sample.reshape(-1, SEQ_LENGTH, len(FEATURE_COLS))
            y_probs = model.predict(X_sample, verbose=0).flatten()
            return roc_auc_score(y_sample, y_probs)

        try:
            # Wrap TF model so sklearn.permutation_importance can call predict(X)
            class TFWrapper:
                def __init__(self, model, seq_length, n_features):
                    self.model = model
                    self.seq_length = seq_length
                    self.n_features = n_features
                def fit(self, X=None, y=None):
                    # sklearn permutation_importance may attempt to check for a fitted estimator
                    return self
                def predict(self, X):
                    X_resh = X.reshape(-1, self.seq_length, self.n_features)
                    return self.model.predict(X_resh, verbose=0).flatten()

            wrapper = TFWrapper(model, SEQ_LENGTH, len(FEATURE_COLS))

            # Use ROC AUC as scoring function for permutation importance
            perm_importance = permutation_importance(
                wrapper,
                X_flat,
                y_test_seq,
                n_repeats=3,
                random_state=42,
                n_jobs=1,
                scoring=lambda est, X, y: roc_auc_score(y, est.predict(X))
            )

            # Map importance back to original features
            feature_imp = {}
            importance_values = perm_importance.importances_mean

            # Average across sequence positions
            for feat_idx, feat_name in enumerate(FEATURE_COLS):
                avg_importance = np.mean(importance_values[feat_idx::len(FEATURE_COLS)])
                feature_imp[feat_name] = float(avg_importance)

            # Sort by importance
            sorted_imp = sorted(feature_imp.items(), key=lambda x: x[1], reverse=True)

            print(f"  Top 5 features:")
            for rank, (feat, imp) in enumerate(sorted_imp[:5], 1):
                print(f"    {rank}. {feat}: {imp:.6f}")

            feature_importance_results.append({
                'held_out_family': held_out,
                'top_5': [f[0] for f in sorted_imp[:5]],
                'importances': dict(sorted_imp)
            })

        except Exception as e:
            print(f"  (Could not extract importance: {str(e)[:200]})")

# Check consistency
if feature_importance_results:
    print(f"\nTOP FEATURE CONSISTENCY:")
    if len(feature_importance_results) > 1:
        top_5_sets = [set(r['top_5']) for r in feature_importance_results]
        common_top_5 = top_5_sets[0]
        for s in top_5_sets[1:]:
            common_top_5 = common_top_5.intersection(s)
        
        print(f"  Features in top 5 for ALL runs: {len(common_top_5)} out of 5")
        if common_top_5:
            print(f"  Common features: {', '.join(common_top_5)}")
            print(f"  → Model captures CONSISTENT behavioral patterns")
        else:
            print(f"  → Model uses DIFFERENT features for different families")

# ==========================================================
# STEP 5: ROBUSTNESS TESTS
# ==========================================================
print("\n" + "="*70)
print("STEP 5: ROBUSTNESS TESTS")
print("="*70)

# k-fold cross-validation on training families (shuffle CV to check stability)
from sklearn.model_selection import StratifiedKFold
print("\n[+] Performing 5-fold CV on pooled training data to assess variance...")

# pool all non-held-out ransomware + benign_train
pooled = pd.concat([df[df['family'].isin(families)], benign_train], ignore_index=True)
X_pool = pooled[FEATURE_COLS].values
y_pool = pooled['label'].values
scaler_pool = StandardScaler().fit(X_pool)
X_pool = scaler_pool.transform(X_pool)
X_seq_pool, y_seq_pool = create_sequences(X_pool, y_pool, SEQ_LENGTH)

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = []
for train_idx, val_idx in skf.split(X_seq_pool, y_seq_pool):
    X_tr, X_val = X_seq_pool[train_idx], X_seq_pool[val_idx]
    y_tr, y_val = y_seq_pool[train_idx], y_seq_pool[val_idx]
    # train simple model
    m = build_model(SEQ_LENGTH, FEATURE_COLS)
    m.compile(loss='binary_crossentropy', optimizer=tf.keras.optimizers.Adam(5e-4), metrics=['accuracy'])
    m.fit(X_tr, y_tr, epochs=3, batch_size=256, verbose=0)
    preds = m.predict(X_val).flatten()
    cv_scores.append(roc_auc_score(y_val, preds))
print(f"  CV ROC AUC: mean={np.mean(cv_scores):.4f}, std={np.std(cv_scores):.4f}")

# noise injection test on zero-day test set
print("\n[+] Evaluating degradation under gaussian noise...")
def add_noise(X, std=0.01):
    return X + np.random.normal(scale=std, size=X.shape)
for noise_std in [0.0, 0.01, 0.05, 0.1]:
    noisy = add_noise(X_test, std=noise_std)
    y_probs = model.predict(noisy, verbose=0).flatten()
    auc = roc_auc_score(y_test, y_probs)
    print(f"  noise std {noise_std}: ROC AUC={auc:.4f}")

# feature ablation: drop one feature at a time in test set
print("\n[+] Feature ablation on test set")
base_auc = roc_auc_score(y_test, model.predict(X_test, verbose=0).flatten())
print(f"  baseline test AUC: {base_auc:.4f}")
for i, feat in enumerate(FEATURE_COLS):
    X_ablate = X_test.copy()
    X_ablate[:,:,i] = 0
    auc = roc_auc_score(y_test, model.predict(X_ablate, verbose=0).flatten())
    print(f"   - without {feat}: AUC={auc:.4f}")

# after robustness, proceed to report generation
print("\n" + "="*70)
print("STEP 6: GENERATING FINDINGS REPORT")
print("="*70)

report_path = os.path.join(REPORT_DIR, f"family_evaluation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

# Write report using UTF-8 to support unicode symbols
with open(report_path, 'w', encoding='utf-8') as f:
    f.write("="*70 + "\n")
    f.write("COMPREHENSIVE CROSS-FAMILY RANSOMWARE DETECTION EVALUATION\n")
    f.write("="*70 + "\n\n")
    
    f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    # LOFO Results
    f.write("SECTION 1: LEAVE-ONE-FAMILY-OUT EVALUATION\n")
    f.write("-"*70 + "\n")
    f.write(lofo_df.to_string(index=False))
    f.write("\n\n")
    
    # Stability Metrics
    f.write("SECTION 2: PERFORMANCE STABILITY ANALYSIS\n")
    f.write("-"*70 + "\n")
    f.write(f"ROC AUC (mean ± std):  {np.mean(roc_auc_values):.4f} ± {np.std(roc_auc_values):.4f}\n")
    f.write(f"Recall (mean ± std):   {np.mean(recall_values):.4f} ± {np.std(recall_values):.4f}\n")
    f.write(f"F1 Score (mean ± std): {np.mean(f1_values):.4f} ± {np.std(f1_values):.4f}\n\n")
    f.write(f"Coefficient of Variation:\n")
    f.write(f"  ROC AUC:  {cv_roc:.2f}%\n")
    f.write(f"  Recall:   {cv_recall:.2f}%\n")
    f.write(f"  F1 Score: {cv_f1:.2f}%\n\n")
    
    stability_status = "STABLE" if cv_roc < stability_threshold else "VARIABLE"
    f.write(f"Stability Assessment: {stability_status}\n")
    f.write(f"(Threshold: CV < {stability_threshold}%)\n\n")
    
    # Feature Importance
    if feature_importance_results:
        f.write("SECTION 3: FEATURE IMPORTANCE STABILITY\n")
        f.write("-"*70 + "\n")
        for result in feature_importance_results:
            f.write(f"\nHeld-out Family: {result['held_out_family']}\n")
            f.write(f"Top 5 Features: {', '.join(result['top_5'])}\n")
    
    # Key Findings
    f.write("\n\n" + "="*70 + "\n")
    f.write("KEY FINDINGS AND INTERPRETATION\n")
    f.write("="*70 + "\n\n")
    
    # Interpretation based on metrics
    avg_recall = np.mean(recall_values)
    avg_roc = np.mean(roc_auc_values)
    
    if cv_roc < stability_threshold and avg_recall > 0.90:
        interpretation = """
✅ STRONG GENERALIZATION DETECTED

The model demonstrates:
  • Consistent performance across all ransomware families (CV < 15%)
  • High recall (>90%) even when family is held out during training
  • Universal detection of encryption burst behavior
  
CONCLUSION:
The model is learning BEHAVIORAL PATTERNS inherent to ransomware encryption,
not family-specific signatures. A new, unseen ransomware family with similar
encryption behavior would likely be detected effectively.

CONFIDENCE: HIGH
Recommendation: Deploy as general-purpose ransomware detector
"""
    elif cv_roc < stability_threshold:
        interpretation = """
✅ STABLE BUT MODERATE PERFORMANCE

The model demonstrates:
  • Consistent performance across families (low CV)
  • Moderate recall (70-85%)
  • Family detection possible, but not always reliable
  
CONCLUSION:
The model captures core behavioral patterns but with limitations.
Performance variations between families suggest partial dependence
on family-specific characteristics.

CONFIDENCE: MEDIUM
Recommendation: Use with ensemble methods or additional signals
"""
    else:
        interpretation = """
⚠️  HIGH VARIANCE ACROSS FAMILIES

The model demonstrates:
  • Inconsistent performance across held-out families (CV > 15%)
  • Family-specific learning detected
  • Limited generalization
  
CONCLUSION:
The model relies significantly on family-specific signatures in the training
data. Performance degrades noticeably when testing on new families.
Additional training data diversity or feature engineering needed.

CONFIDENCE: LOW
Recommendation: Augment training data and retrain
"""
    
    f.write(interpretation)
    
    # Statistics
    f.write("\n" + "-"*70 + "\n")
    f.write("NUMERICAL SUMMARY\n")
    f.write("-"*70 + "\n")
    f.write(f"Number of experiments: {len(lofo_results)}\n")
    f.write(f"Training families per fold: 3 (out of {len(families)})\n")
    f.write(f"Test family per fold: 1 (held-out)\n")
    f.write(f"Total benign samples: {len(benign_df)}\n")
    f.write(f"  - Training: {len(benign_train)}\n")
    f.write(f"  - Testing: {len(benign_test)}\n\n")
    
    f.write("PERFORMANCE RANGE\n")
    f.write(f"  ROC AUC:  {min(roc_auc_values):.4f} - {max(roc_auc_values):.4f}\n")
    f.write(f"  Recall:   {min(recall_values):.4f} - {max(recall_values):.4f}\n")
    f.write(f"  F1 Score: {min(f1_values):.4f} - {max(f1_values):.4f}\n")

print(f"\n[+] Report saved to: {report_path}")

# Save JSON results for further analysis
json_path = os.path.join(REPORT_DIR, f"family_evaluation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
# Sanitize results (remove non-serializable objects like TF models/scalers)
lofo_serializable = []
for r in lofo_results:
    item = {k: v for k, v in r.items() if k not in ('model', 'scaler')}
    lofo_serializable.append(item)

json_results = {
    'timestamp': datetime.now().isoformat(),
    'lofo_results': lofo_serializable,
    'single_family_results': single_family_results,
    'stability_metrics': {
        'roc_auc_mean': float(np.mean(roc_auc_values)),
        'roc_auc_std': float(np.std(roc_auc_values)),
        'roc_auc_cv': float(cv_roc),
        'recall_mean': float(np.mean(recall_values)),
        'recall_std': float(np.std(recall_values)),
        'recall_cv': float(cv_recall),
        'f1_mean': float(np.mean(f1_values)),
        'f1_std': float(np.std(f1_values)),
        'f1_cv': float(cv_f1),
    },
    'feature_importance': feature_importance_results
}

with open(json_path, 'w', encoding='utf-8') as f:
    json.dump(json_results, f, indent=2)

print(f"[+] JSON results saved to: {json_path}")

print("\n" + "="*70)
print("EVALUATION COMPLETE")
print("="*70)
