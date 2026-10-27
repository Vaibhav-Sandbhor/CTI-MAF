"""
_patch_predictor.py -- update ransomware_module/models/predict_lstm.py
to support sklearn mlp_model.pkl when TF is unavailable.
"""
from pathlib import Path

SRC = Path("ransomware_module/models/predict_lstm.py")

with open(SRC, encoding="utf-8") as f:
    content = f.read()

if "mlp_model" in content:
    print("predict_lstm.py already supports sklearn. Nothing to do.")
    exit(0)

# Add sklearn import path and model constants after DEFAULT_SCALER_PATH
OLD_DEFAULTS = 'DEFAULT_SCALER_PATH = _MODELS_DIR / "scaler.pkl"\nDEFAULT_THR_PATH    = _MODELS_DIR / "threshold.txt"'
NEW_DEFAULTS = 'DEFAULT_SCALER_PATH = _MODELS_DIR / "scaler.pkl"\nDEFAULT_MLP_PATH    = _MODELS_DIR / "mlp_model.pkl"\nDEFAULT_THR_PATH    = _MODELS_DIR / "threshold.txt"'
content = content.replace(OLD_DEFAULTS, NEW_DEFAULTS, 1)

# Replace the _ensure_loaded method to add sklearn support
OLD_ENSURE = '''    def _ensure_loaded(self) -> None:
        if self._model is not None and self._scaler is not None:
            return
        if not self._model_path.exists():
            raise FileNotFoundError(
                f"LSTM model not found: {self._model_path}\\n"
                f"Run: python -m ransomware_module.scripts.train_model"
            )
        if not self._scaler_path.exists():
            raise FileNotFoundError(
                f"Scaler not found: {self._scaler_path}\\n"
                f"Run: python -m ransomware_module.scripts.train_model"
            )
        if not _tf_available():
            raise ImportError("TensorFlow is not available in this environment.")
        load_model = _import_keras_load()
        print(f"[PREDICT] Loading model  : {self._model_path}")
        print(f"[PREDICT] Loading scaler : {self._scaler_path}")
        self._model  = load_model(str(self._model_path))
        self._scaler = joblib.load(str(self._scaler_path))'''

NEW_ENSURE = '''    def _ensure_loaded(self) -> None:
        if self._model is not None and self._scaler is not None:
            return

        # Try sklearn MLP first (always available, no DLL issues)
        mlp_path = DEFAULT_MLP_PATH
        if mlp_path.exists() and self._scaler_path.exists():
            print(f"[PREDICT] Loading sklearn MLP: {mlp_path}")
            print(f"[PREDICT] Loading scaler     : {self._scaler_path}")
            self._model  = joblib.load(str(mlp_path))
            self._scaler = joblib.load(str(self._scaler_path))
            self._backend = "sklearn"
            return

        # Fallback to TF LSTM
        if not self._model_path.exists():
            raise FileNotFoundError(
                f"No model found. Run: python -m ransomware_module.scripts.train_model"
            )
        if not self._scaler_path.exists():
            raise FileNotFoundError(
                f"Scaler not found: {self._scaler_path}"
            )
        if not _tf_available():
            raise ImportError(
                "TensorFlow is not available and no sklearn model found. "
                "Run: python -m ransomware_module.scripts.train_model --force-sklearn"
            )
        load_model = _import_keras_load()
        print(f"[PREDICT] Loading LSTM model : {self._model_path}")
        print(f"[PREDICT] Loading scaler     : {self._scaler_path}")
        self._model  = load_model(str(self._model_path))
        self._scaler = joblib.load(str(self._scaler_path))
        self._backend = "tensorflow"'''

content = content.replace(OLD_ENSURE, NEW_ENSURE, 1)

# Add _backend attribute initialisation in __init__
OLD_INIT_END = '        self._model_path  = Path(model_path)\n        self._scaler_path = Path(scaler_path)'
NEW_INIT_END = '        self._model_path  = Path(model_path)\n        self._scaler_path = Path(scaler_path)\n        self._backend: str = "unknown"'
content = content.replace(OLD_INIT_END, NEW_INIT_END, 1)

# Fix predict_dict to handle sklearn models (no 3-D reshape needed)
OLD_PREDICT = '''        X = prepare_features(df, scaler)
        probs = model.predict(X)'''

# This appears in a different function -- find predict_dataframe
# Let's fix the single-row predict_dict to handle sklearn
OLD_SINGLE = '''        seq = self._build_sequence(scaled[0])
        prob = float(self._model.predict(seq, verbose=0)[0][0])'''
NEW_SINGLE = '''        if self._backend == "sklearn":
            prob = float(self._model.predict_proba(scaled)[0][1])
        else:
            seq  = self._build_sequence(scaled[0])
            prob = float(self._model.predict(seq, verbose=0)[0][0])'''
content = content.replace(OLD_SINGLE, NEW_SINGLE, 1)

# Fix batch predict_dataframe for sklearn
OLD_BATCH = '''        X_seq  = scaled.reshape(X.shape[0], 1, N_FEATURES)
        probs  = self._model.predict(X_seq, verbose=0).flatten()'''
NEW_BATCH = '''        if self._backend == "sklearn":
            probs = self._model.predict_proba(scaled)[:, 1].astype(float).flatten()
        else:
            X_seq = scaled.reshape(X.shape[0], 1, N_FEATURES)
            probs = self._model.predict(X_seq, verbose=0).flatten()'''
content = content.replace(OLD_BATCH, NEW_BATCH, 1)

with open(SRC, "w", encoding="utf-8") as f:
    f.write(content)

print("predict_lstm.py patched successfully.")
print("Has mlp_model:", "mlp_model" in content)
print("Has sklearn backend:", "sklearn" in content)
