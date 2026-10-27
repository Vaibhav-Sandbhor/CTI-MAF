"""
Safe Model Retraining Pipeline
- Monitors new_scan_logs.csv
- Retrains only when 200+ rows accumulated
- Compares performance with previous model
- Only replaces model if F1-score improves
- Maintains version control of models
"""

import os
import csv
import pandas as pd
import joblib
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, confusion_matrix, accuracy_score, precision_score, recall_score
from feature_engineering import parse_nmap, calculate_features

# ────────────────────────────────
# CONFIGURATION
# ────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MODEL_DIR = os.path.join(PROJECT_ROOT, "model")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")

SCAN_LOGS_FILE = os.path.join(DATA_DIR, "new_scan_logs.csv")
HISTORICAL_DATASET = os.path.join(DATA_DIR, "dataset.csv")
SYSTEM_LOG = os.path.join(LOGS_DIR, "system.log")
RETRAIN_LOG = os.path.join(LOGS_DIR, "retrain_events.log")

# Create logs directory if missing
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

# Retraining threshold
MIN_NEW_SAMPLES = 200


# ────────────────────────────────
# UTILITY FUNCTIONS
# ────────────────────────────────
def log_event(log_file, message):
    """Log events to file with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] {message}"
    
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")
    
    print(log_msg)


def load_current_model():
    """Load the latest trained model"""
    if not os.path.exists(MODEL_DIR):
        log_event(SYSTEM_LOG, "❌ MODEL_DIR not found. No model to load.")
        return None
    
    model_files = [f for f in os.listdir(MODEL_DIR) if f.endswith(".pkl")]
    
    if not model_files:
        log_event(SYSTEM_LOG, "❌ No trained model found.")
        return None
    
    latest_model = sorted(model_files)[-1]
    model_path = os.path.join(MODEL_DIR, latest_model)
    
    model = joblib.load(model_path)
    log_event(SYSTEM_LOG, f"✅ Loaded current model: {latest_model}")
    
    return model


def evaluate_model_performance(model, X_test, y_test):
    """Evaluate model using multiple metrics"""
    predictions = model.predict(X_test)
    
    f1 = f1_score(y_test, predictions, average='weighted', zero_division=0)
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, average='weighted', zero_division=0)
    recall = recall_score(y_test, predictions, average='weighted', zero_division=0)
    
    metrics = {
        "f1_score": f1,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall
    }
    
    return metrics


def check_retraining_eligibility():
    """
    Check if we have enough new data to retrain
    Returns: (eligible: bool, new_samples_count: int)
    """
    if not os.path.exists(SCAN_LOGS_FILE):
        log_event(SYSTEM_LOG, "❌ new_scan_logs.csv not found. Cannot check retraining eligibility.")
        return False, 0
    
    try:
        df = pd.read_csv(SCAN_LOGS_FILE)
        sample_count = len(df)
        
        if sample_count >= MIN_NEW_SAMPLES:
            log_event(SYSTEM_LOG, f"✅ New scan logs have {sample_count} samples (threshold: {MIN_NEW_SAMPLES}). Retraining eligible.")
            return True, sample_count
        else:
            remaining = MIN_NEW_SAMPLES - sample_count
            log_event(SYSTEM_LOG, f"⏳ New scan logs have {sample_count} samples. Need {remaining} more for retraining.")
            return False, sample_count
    
    except Exception as e:
        log_event(SYSTEM_LOG, f"❌ Error reading scan logs: {str(e)}")
        return False, 0


def prepare_training_data():
    """
    Prepare training data from:
    - Historical dataset.csv (primary)
    - new_scan_logs.csv (new data)
    Returns: (X_train, y_train, X_test, y_test)
    """
    dfs = []
    
    # Load historical data
    if os.path.exists(HISTORICAL_DATASET):
        hist_df = pd.read_csv(HISTORICAL_DATASET)
        log_event(SYSTEM_LOG, f"📊 Loaded {len(hist_df)} historical samples")
        dfs.append(hist_df)
    
    # Load new scan logs
    if os.path.exists(SCAN_LOGS_FILE):
        new_df = pd.read_csv(SCAN_LOGS_FILE)
        log_event(SYSTEM_LOG, f"📊 Loaded {len(new_df)} new scan samples")
        # Convert columns if necessary
        if 'label' in new_df.columns:
            new_df = new_df.rename(columns={'predicted_label': 'label'})
        dfs.append(new_df)
    
    if not dfs:
        log_event(SYSTEM_LOG, "❌ No training data available.")
        return None, None, None, None
    
    # Combine datasets
    combined_df = pd.concat(dfs, ignore_index=True)
    log_event(SYSTEM_LOG, f"📊 Combined dataset: {len(combined_df)} total samples")
    
    # Extract features and labels
    feature_cols = ["open_ports_count", "service_count", "avg_cvss", "uncommon_ports", "os_flag"]
    X = combined_df[feature_cols].values
    
    # Handle label column variations
    if 'label' in combined_df.columns:
        y = combined_df['label'].values
    elif 'predicted_label' in combined_df.columns:
        y = combined_df['predicted_label'].values
    else:
        log_event(SYSTEM_LOG, "❌ No label column found in training data.")
        return None, None, None, None
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    log_event(SYSTEM_LOG, f"✅ Train/Test split: {len(X_train)} / {len(X_test)}")
    
    return X_train, y_train, X_test, y_test


def train_new_model(X_train, y_train):
    """Train a new Random Forest model"""
    log_event(SYSTEM_LOG, "🤖 Training new Random Forest model...")
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    log_event(SYSTEM_LOG, "✅ Model training completed")
    
    return model


def save_versioned_model(model):
    """Save model with version timestamp"""
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_name = f"rf_model_{timestamp}.pkl"
    model_path = os.path.join(MODEL_DIR, model_name)
    
    joblib.dump(model, model_path)
    log_event(SYSTEM_LOG, f"💾 Saved model: {model_name}")
    
    return model_path


def compare_model_performance(old_metrics, new_metrics):
    """
    Compare old and new model performance
    Returns: (improvement_detected: bool, improvement_percent: float)
    """
    if old_metrics is None:
        log_event(SYSTEM_LOG, "📊 No previous model for comparison. New model is baseline.")
        return True, 100.0
    
    old_f1 = old_metrics.get("f1_score", 0)
    new_f1 = new_metrics.get("f1_score", 0)
    
    improvement = ((new_f1 - old_f1) / (old_f1 + 1e-10)) * 100
    
    log_event(SYSTEM_LOG, f"📊 F1-Score Comparison:")
    log_event(SYSTEM_LOG, f"   Old Model F1: {old_f1:.4f}")
    log_event(SYSTEM_LOG, f"   New Model F1: {new_f1:.4f}")
    log_event(SYSTEM_LOG, f"   Improvement: {improvement:+.2f}%")
    
    if new_f1 > old_f1:
        return True, improvement
    else:
        return False, improvement


def execute_safe_retrain():
    """Main retraining pipeline with safety checks"""
    
    log_event(SYSTEM_LOG, "\n" + "="*70)
    log_event(SYSTEM_LOG, "🔄 SAFE RETRAINING PIPELINE STARTED")
    log_event(SYSTEM_LOG, "="*70)
    
    # Step 1: Check eligibility
    eligible, sample_count = check_retraining_eligibility()
    
    if not eligible:
        log_event(SYSTEM_LOG, "⏹️  Retraining not yet eligible. Exiting.")
        return False
    
    # Step 2: Load current model for comparison
    current_model = load_current_model()
    current_metrics = None
    
    if current_model is not None:
        log_event(SYSTEM_LOG, "📊 Evaluating current model performance...")
        # We'll evaluate after getting test data
    
    # Step 3: Prepare training data
    X_train, y_train, X_test, y_test = prepare_training_data()
    
    if X_train is None:
        log_event(SYSTEM_LOG, "❌ Failed to prepare training data. Aborting retraining.")
        return False
    
    # Evaluate current model if available
    if current_model is not None:
        current_metrics = evaluate_model_performance(current_model, X_test, y_test)
        log_event(SYSTEM_LOG, f"📊 Current Model Metrics:")
        for metric, value in current_metrics.items():
            log_event(SYSTEM_LOG, f"   {metric}: {value:.4f}")
    
    # Step 4: Train new model
    new_model = train_new_model(X_train, y_train)
    new_metrics = evaluate_model_performance(new_model, X_test, y_test)
    
    log_event(SYSTEM_LOG, f"📊 New Model Metrics:")
    for metric, value in new_metrics.items():
        log_event(SYSTEM_LOG, f"   {metric}: {value:.4f}")
    
    # Step 5: Compare performance
    improvement, improvement_percent = compare_model_performance(current_metrics, new_metrics)
    
    # Step 6: Decision
    if improvement:
        log_event(SYSTEM_LOG, "✅ NEW MODEL PERFORMS BETTER - DEPLOYING")
        model_path = save_versioned_model(new_model)
        
        # Also save as current model (latest)
        latest_path = os.path.join(MODEL_DIR, "rf_model.pkl")
        joblib.dump(new_model, latest_path)
        log_event(SYSTEM_LOG, f"✅ Updated active model: rf_model.pkl")
        
        log_event(RETRAIN_LOG, f"✅ MODEL REPLACEMENT: Old F1={current_metrics.get('f1_score', 'N/A'):.4f} → New F1={new_metrics['f1_score']:.4f} (+{improvement_percent:.2f}%)")
        
        return True
    else:
        log_event(SYSTEM_LOG, "❌ NEW MODEL DOES NOT IMPROVE - KEEPING CURRENT")
        log_event(RETRAIN_LOG, f"❌ MODEL REJECTED: New F1={new_metrics['f1_score']:.4f} vs Current F1={current_metrics.get('f1_score', 'N/A'):.4f} ({improvement_percent:+.2f}%)")
        
        # Save new model as backup for analysis
        backup_path = save_versioned_model(new_model)
        log_event(SYSTEM_LOG, f"💾 Saved new model as backup (not deployed): {os.path.basename(backup_path)}")
        
        return False


# ────────────────────────────────
# MAIN
# ────────────────────────────────
if __name__ == "__main__":
    try:
        success = execute_safe_retrain()
        
        if success:
            log_event(SYSTEM_LOG, "✅ RETRAINING COMPLETED SUCCESSFULLY")
        else:
            log_event(SYSTEM_LOG, "⏹️  RETRAINING SKIPPED OR FAILED")
        
        log_event(SYSTEM_LOG, "="*70 + "\n")
    
    except Exception as e:
        log_event(SYSTEM_LOG, f"❌ CRITICAL ERROR: {str(e)}")
        import traceback
        log_event(SYSTEM_LOG, traceback.format_exc())
