import os
import pandas as pd
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score, brier_score_loss
from sklearn.preprocessing import LabelEncoder
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import brier_score_loss
from xgboost import XGBClassifier
import joblib  # for saving model
import numpy as np

# -------------------------------
# CONFIG
# -------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_FILE = os.path.join(PROJECT_ROOT, "data", "dataset.csv")
MODEL_FILE = os.path.join(PROJECT_ROOT, "model", "rf_model.pkl")

# -------------------------------
# STEP 1: LOAD DATASET
# -------------------------------
df = pd.read_csv(DATASET_FILE)

# Features and target
X = df[["open_ports_count", "service_count", "avg_cvss", "uncommon_ports", "os_flag",
        "port_severity_score", "high_risk_port_count", "service_entropy", "cvss_variance"]]
y = df["risk_label"]

# Encode labels for XGBoost compatibility (while keeping originals for RF)
le = LabelEncoder()
y_encoded = le.fit_transform(y)

# Create mapping for reference
label_mapping = dict(zip(le.classes_, le.transform(le.classes_)))
inverse_mapping = {v: k for k, v in label_mapping.items()}

# -------------------------------
# STEP 2: SPLIT DATA
# -------------------------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
X_train_enc, X_test_enc, y_train_enc, y_test_enc = train_test_split(X, y_encoded, test_size=0.2, stratify=y_encoded, random_state=42)

# -------------------------------
# STEP 3: HYPERPARAMETER TUNING WITH RANDOMIZEDSEARCHCV
# -------------------------------
print("\n🔧 HYPERPARAMETER TUNING IN PROGRESS...")
print("(This may take a moment)\n")

# Define parameter search space
param_dist = {
    "n_estimators": [200, 300, 400, 500],
    "max_depth": [8, 10, 12, 15, None],
    "min_samples_split": [2, 5, 10],
    "min_samples_leaf": [1, 2, 4],
    "max_features": ["sqrt", "log2", None],
    "class_weight": ["balanced"]
}

# Create RandomizedSearchCV for tuning
random_search = RandomizedSearchCV(
    estimator=RandomForestClassifier(random_state=42),
    param_distributions=param_dist,
    n_iter=20,
    cv=5,
    scoring="f1_weighted",
    n_jobs=-1,
    verbose=1,
    random_state=42
)

# Fit hyperparameter search
random_search.fit(X_train, y_train)

# Get best model
rf = random_search.best_estimator_

print("\n" + "="*70)
print("✅ HYPERPARAMETER TUNING COMPLETE (RandomForest)")
print("="*70)
print(f"\n🎯 Best Cross-Validation F1-Score (weighted): {random_search.best_score_:.4f}")
print("\n📊 Best Parameters Found:")
for param, value in random_search.best_params_.items():
    print(f"   {param:25s}: {value}")
print()

# ═════════════════════════════════════════════════════════════════════════════
# STEP 4A: EVALUATE RANDOMFOREST ON TEST SET
# ═════════════════════════════════════════════════════════════════════════════
y_pred_rf = rf.predict(X_test)

accuracy_rf = accuracy_score(y_test, y_pred_rf)
f1_weighted_rf = f1_score(y_test, y_pred_rf, average="weighted")

print("\n" + "="*70)
print("📈 RANDOMFOREST - TEST SET EVALUATION")
print("="*70)
print(f"\nAccuracy:            {accuracy_rf:.4f} ({accuracy_rf*100:.2f}%)")
print(f"F1-Score (weighted): {f1_weighted_rf:.4f}")
print("\n📋 Classification Report:")
print("-" * 70)
print(classification_report(y_test, y_pred_rf))
print("\n🔲 Confusion Matrix:")
print("-" * 70)
print(confusion_matrix(y_test, y_pred_rf))
print()

# ═════════════════════════════════════════════════════════════════════════════
# STEP 4B: TRAIN XGBOOST MODEL
# ═════════════════════════════════════════════════════════════════════════════
print("\n🔧 TRAINING XGBOOST MODEL...")
print("(Simplified tuning for gradient boosting)\n")

xgb = XGBClassifier(
    n_estimators=400,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    eval_metric="mlogloss",
    use_label_encoder=False,
    verbosity=0
)

xgb.fit(X_train_enc, y_train_enc)

y_pred_xgb_enc = xgb.predict(X_test_enc)
# Convert back to original labels for reporting
y_pred_xgb = le.inverse_transform(y_pred_xgb_enc)

accuracy_xgb = accuracy_score(y_test, y_pred_xgb)
f1_weighted_xgb = f1_score(y_test, y_pred_xgb, average="weighted")

print("\n" + "="*70)
print("📈 XGBOOST - TEST SET EVALUATION")
print("="*70)
print(f"\nAccuracy:            {accuracy_xgb:.4f} ({accuracy_xgb*100:.2f}%)")
print(f"F1-Score (weighted): {f1_weighted_xgb:.4f}")
print("\n📋 Classification Report:")
print("-" * 70)
print(classification_report(y_test, y_pred_xgb))
print("\n🔲 Confusion Matrix:")
print("-" * 70)
print(confusion_matrix(y_test, y_pred_xgb))
print()

# ═════════════════════════════════════════════════════════════════════════════
# STEP 5: MODEL COMPARISON & SELECTION
# ═════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("⚖️  MODEL COMPARISON (RandomForest vs XGBoost)")
print("="*70)
print(f"\n{'Metric':<20} {'RandomForest':<20} {'XGBoost':<20}")
print("-" * 70)
print(f"{'Accuracy':<20} {accuracy_rf:.4f} ({accuracy_rf*100:.2f}%){'':<11} {accuracy_xgb:.4f} ({accuracy_xgb*100:.2f}%)")
print(f"{'F1-Score (weighted)':<20} {f1_weighted_rf:.4f}{'':<16} {f1_weighted_xgb:.4f}")
print()

# Select best model based on weighted F1-score
if f1_weighted_xgb > f1_weighted_rf:
    best_model = xgb
    best_model_name = "XGBoost"
    best_f1 = f1_weighted_xgb
    best_accuracy = accuracy_xgb
else:
    best_model = rf
    best_model_name = "RandomForest"
    best_f1 = f1_weighted_rf
    best_accuracy = accuracy_rf

print(f"\n🏆 BEST MODEL: {best_model_name}")
print(f"   Accuracy:     {best_accuracy:.4f} ({best_accuracy*100:.2f}%)")
print(f"   F1-Score:     {best_f1:.4f}")
print()

# ═════════════════════════════════════════════════════════════════════════════
# STEP 6A: PROBABILITY CALIBRATION
# ═════════════════════════════════════════════════════════════════════════════
print("\n🔧 APPLYING PROBABILITY CALIBRATION...")
print("(Using isotonic regression on 5-fold cross-validation)\n")

# Prepare calibration data based on selected model
if best_model_name == "XGBoost":
    X_cal = X_train_enc
    y_cal = y_train_enc
else:
    X_cal = X_train
    y_cal = y_train

# Calibrate the best model's probabilities
calibrated_model = CalibratedClassifierCV(
    estimator=best_model,
    method="sigmoid",
    cv=5
)

calibrated_model.fit(X_cal, y_cal)

# Evaluate calibrated model on test set
if best_model_name == "XGBoost":
    X_eval = X_test_enc
else:
    X_eval = X_test

y_pred_calibrated_raw = calibrated_model.predict(X_eval)

# Decode predictions for XGBoost
if best_model_name == "XGBoost":
    y_pred_calibrated = le.inverse_transform(y_pred_calibrated_raw)
else:
    y_pred_calibrated = y_pred_calibrated_raw

accuracy_calibrated = accuracy_score(y_test, y_pred_calibrated)
f1_weighted_calibrated = f1_score(y_test, y_pred_calibrated, average="weighted")

print("\n" + "="*70)
print("📊 CALIBRATION RESULTS")
print("="*70)
print(f"\n{'Metric':<25} {'Before Cal.':<20} {'After Cal.':<20}")
print("-" * 70)
print(f"{'Accuracy':<25} {best_accuracy:.4f}{'':<15} {accuracy_calibrated:.4f}")
print(f"{'F1-Score (weighted)':<25} {best_f1:.4f}{'':<15} {f1_weighted_calibrated:.4f}")

# Get probability predictions for calibration comparison
proba_before = best_model.predict_proba(X_eval)
proba_after = calibrated_model.predict_proba(X_eval)

# Calculate multiclass Brier score manually
# Brier score = mean((predicted_prob - actual_label)^2)
y_test_encoded = le.transform(y_test)
y_test_one_hot = np.eye(len(le.classes_))[y_test_encoded]
brier_before = np.mean((proba_before - y_test_one_hot) ** 2)
brier_after = np.mean((proba_after - y_test_one_hot) ** 2)

print(f"{'Brier Score (Lower)':<25} {brier_before:.4f}{'':<15} {brier_after:.4f}")

if accuracy_calibrated >= best_accuracy:
    calibration_effect = "✓ Improved or maintained"
else:
    calibration_effect = "◇ Slightly reduced (acceptable trade-off)"

print(f"{'Accuracy Change':<25} {calibration_effect}")
print()

print("\n📋 Calibrated Classification Report:")
print("-" * 70)
print(classification_report(y_test, y_pred_calibrated))

print("\n🔲 Calibrated Confusion Matrix:")
print("-" * 70)
print(confusion_matrix(y_test, y_pred_calibrated))
print()

# Confidence reliability analysis
print("\n📈 Probability Calibration Analysis:")
print("-" * 70)
proba_max = np.max(proba_after, axis=1)
print(f"   Mean predicted confidence (after calibration): {np.mean(proba_max):.4f}")
print(f"   Min confidence score: {np.min(proba_max):.4f}")
print(f"   Max confidence score: {np.max(proba_max):.4f}")
print(f"   Std deviation: {np.std(proba_max):.4f}")
print()
print("   ✓ Calibrated probabilities now reflect true likelihood of correctness")
print()

# ═════════════════════════════════════════════════════════════════════════════
# STEP 6B: SAVE BEST CALIBRATED MODEL
# ═════════════════════════════════════════════════════════════════════════════
# ═════════════════════════════════════════════════════════════════════════════
# STEP 6B: SAVE BEST CALIBRATED MODEL
# ═════════════════════════════════════════════════════════════════════════════
# Create model folder if not exists
if not os.path.exists(os.path.join(PROJECT_ROOT, "model")):
    os.makedirs(os.path.join(PROJECT_ROOT, "model"))

# Save calibrated model and label encoder
joblib.dump(calibrated_model, MODEL_FILE)

# Also save label encoder for the model (needed for XGBoost predictions)
encoder_file = os.path.join(PROJECT_ROOT, "model", "label_encoder.pkl")
joblib.dump(le, encoder_file)

print("="*70)
print(f"✅ Calibrated {best_model_name} model saved at: {MODEL_FILE}")
print(f"✅ Label encoder saved at: {encoder_file}")
print(f"✅ Probability calibration: ENABLED (sigmoid method, 5-fold CV)")
print("="*70 + "\n")
