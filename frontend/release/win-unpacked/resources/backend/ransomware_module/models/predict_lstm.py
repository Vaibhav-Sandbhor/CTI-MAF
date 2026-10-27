"""
predict_lstm.py  (ransomware_module)
=====================================
Module 3: LSTM Ransomware Detection Model — Prediction Layer

Loads the trained LSTM model and scaler from:
    ransomware_module/models/lstm_model.keras  (or .h5)
    ransomware_module/models/scaler.pkl

and exposes a clean API for:
    • Single-row prediction (dict -> threat label + confidence)
    • Batch prediction (DataFrame -> probabilities + labels)
    • CLI batch scoring

Threshold behaviour:
    Default  = 0.50  (balanced)
    Production = 0.70 (high-precision, low FPR — recommended)
    High-recall = 0.35 (maximise TP at expense of FP)

Usage:
    # From CLI:
    python -m ransomware_module.models.predict_lstm \\
        --input data/live_input.csv --output output/predictions_log.csv

    # From API:
    from ransomware_module.models.predict_lstm import RansomwareDetector
    det = RansomwareDetector()
    result = det.predict_dict({"entropy": 7.8, "extension_change": 1, ...})
    print(result)   # {"prediction": "RANSOMWARE", "confidence": 0.97, ...}
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
_MODULE_ROOT = Path(__file__).resolve().parent.parent
_MODELS_DIR  = _MODULE_ROOT / "models"

DEFAULT_MODEL_PATH  = _MODELS_DIR / "lstm_model.keras"
DEFAULT_H5_PATH     = _MODELS_DIR / "lstm_model.h5"
DEFAULT_SCALER_PATH = _MODELS_DIR / "scaler.pkl"
DEFAULT_MLP_PATH    = _MODELS_DIR / "mlp_model.pkl"
DEFAULT_THR_PATH    = _MODELS_DIR / "threshold.txt"

# Feature ordering MUST match training order
from ransomware_module.utils.feature_extractor import (
    BEHAVIORAL_FEATURES,
    N_FEATURES,
    classify_threat,
    threat_to_alert_level,
    validate_feature_row,
)

SEQ_LEN = 5   # must match training sequence length


# ---------------------------------------------------------------------------
# TensorFlow safe-import guard
# ---------------------------------------------------------------------------

def _tf_available() -> bool:
    """Test TF availability in a subprocess to avoid in-process crashes."""
    import subprocess
    try:
        subprocess.check_call(
            [sys.executable, "-c", "import tensorflow"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
        return True
    except Exception:
        return False


def _import_keras_load():
    try:
        from tensorflow.keras.models import load_model as _lm
        return _lm
    except Exception as exc:
        raise ImportError("TensorFlow/Keras unavailable") from exc


# ---------------------------------------------------------------------------
# Threshold persistence
# ---------------------------------------------------------------------------

def load_threshold(default: float = 0.50) -> float:
    if DEFAULT_THR_PATH.exists():
        try:
            return float(DEFAULT_THR_PATH.read_text().strip())
        except Exception:
            pass
    return default


def save_threshold(value: float) -> None:
    DEFAULT_THR_PATH.write_text(str(value))


# ---------------------------------------------------------------------------
# RansomwareDetector
# ---------------------------------------------------------------------------

class RansomwareDetector:
    """
    Wraps the trained LSTM model + scaler for inference.

    Parameters
    ----------
    model_path  : path to .keras or .h5 file
    scaler_path : path to scaler.pkl
    threshold   : decision boundary for positive class (default 0.50)
    seq_len     : sequence length used during training (default 5)
    """

    def __init__(
        self,
        model_path:  Optional[Path] = None,
        scaler_path: Optional[Path] = None,
        threshold:   float = 0.50,
        seq_len:     int   = SEQ_LEN,
    ) -> None:
        self.seq_len = seq_len
        self.threshold = threshold
        self._model  = None
        self._scaler = None
        self._history: List[np.ndarray] = []   # rolling feature buffer for sequences

        # Resolve paths
        if model_path is None:
            model_path = DEFAULT_MODEL_PATH if DEFAULT_MODEL_PATH.exists() else DEFAULT_H5_PATH
        if scaler_path is None:
            scaler_path = DEFAULT_SCALER_PATH

        self._model_path  = Path(model_path)
        self._scaler_path = Path(scaler_path)
        self._backend: str = "unknown"

    # ------------------------------------------------------------------
    # Lazy loading
    # ------------------------------------------------------------------

    def _ensure_loaded(self) -> None:
        if self._model is not None and self._scaler is not None:
            return
        # Try sklearn MLP first (no TF DLL dependency)
        if DEFAULT_MLP_PATH.exists() and self._scaler_path.exists():
            print(f"[PREDICT] Loading sklearn MLP: {DEFAULT_MLP_PATH}")
            print(f"[PREDICT] Loading scaler     : {self._scaler_path}")
            self._model   = joblib.load(str(DEFAULT_MLP_PATH))
            self._scaler  = joblib.load(str(self._scaler_path))
            self._backend = "sklearn"
            return
        if not self._model_path.exists():
            raise FileNotFoundError(
                f"LSTM model not found: {self._model_path}\n"
                f"Run: python -m ransomware_module.scripts.train_model"
            )
        if not self._scaler_path.exists():
            raise FileNotFoundError(
                f"Scaler not found: {self._scaler_path}\n"
                f"Run: python -m ransomware_module.scripts.train_model"
            )
        if not _tf_available():
            raise ImportError("TensorFlow is not available in this environment.")
        load_model = _import_keras_load()
        print(f"[PREDICT] Loading model  : {self._model_path}")
        print(f"[PREDICT] Loading scaler : {self._scaler_path}")
        self._model   = load_model(str(self._model_path))
        self._scaler  = joblib.load(str(self._scaler_path))
        self._backend = "tensorflow"

    # ------------------------------------------------------------------
    # Feature preparation
    # ------------------------------------------------------------------

    def _features_from_dict(self, row: Dict) -> np.ndarray:
        """Validate + extract 1-D feature vector from a dict."""
        d = validate_feature_row(row)
        return np.array([d[f] for f in BEHAVIORAL_FEATURES], dtype=np.float32)

    def _scale(self, X: np.ndarray) -> np.ndarray:
        """Scale a (n, N_FEATURES) matrix using the fitted scaler."""
        return self._scaler.transform(X).astype(np.float32)

    def _build_sequence(self, vec: np.ndarray) -> np.ndarray:
        """
        Maintain a rolling buffer and return the latest sequence as
        (1, seq_len, N_FEATURES) ready for model.predict.
        """
        self._history.append(vec)
        if len(self._history) > self.seq_len:
            self._history.pop(0)
        # Pad with zeros if history is shorter than seq_len
        buf = list(self._history)
        while len(buf) < self.seq_len:
            buf.insert(0, np.zeros(N_FEATURES, dtype=np.float32))
        seq = np.stack(buf, axis=0)              # (seq_len, N_FEATURES)
        return seq.reshape(1, self.seq_len, N_FEATURES)

    # ------------------------------------------------------------------
    # Single-row prediction
    # ------------------------------------------------------------------

    def predict_dict(self, row: Dict, source: str = "BEHAVIORAL") -> Dict:
        """
        Predict ransomware probability for a single feature dict.

        Returns
        -------
        {
          "prediction":   "RANSOMWARE" | "SUSPICIOUS" | "BENIGN",
          "confidence":   float [0,1],
          "threat_level": "CRITICAL" | "WARNING" | "INFO",
          "source":       str,
        }
        """
        self._ensure_loaded()
        vec = self._features_from_dict(row)
        scaled = self._scale(vec.reshape(1, N_FEATURES))
        if self._backend == "sklearn":
            prob = float(self._model.predict_proba(scaled)[0][1])
        else:
            seq  = self._build_sequence(scaled[0])
            prob = float(self._model.predict(seq, verbose=0)[0][0])
        prediction = classify_threat(prob)
        return {
            "prediction":   prediction,
            "confidence":   round(prob, 4),
            "threat_level": threat_to_alert_level(prediction),
            "source":       source,
        }

    # ------------------------------------------------------------------
    # Batch DataFrame prediction
    # ------------------------------------------------------------------

    def predict_dataframe(
        self,
        df,                        # pandas.DataFrame
        threshold: Optional[float] = None,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Score every row in *df* independently (no sequence context).

        Returns
        -------
        probs : ndarray shape (n,) – ransomware probabilities
        preds : ndarray shape (n,) – binary 0/1 labels
        """
        self._ensure_loaded()
        import pandas as pd

        thr = threshold if threshold is not None else self.threshold

        # Select numeric feature columns
        feat_cols = [c for c in BEHAVIORAL_FEATURES if c in df.columns]
        X = df[feat_cols].fillna(0).values.astype(np.float32)

        # Pad missing feature columns with zeros
        if X.shape[1] < N_FEATURES:
            pad = np.zeros((X.shape[0], N_FEATURES - X.shape[1]), dtype=np.float32)
            X = np.hstack([X, pad])

        scaled = self._scale(X)                          # (n, N_FEATURES)
        if self._backend == "sklearn":
            probs = self._model.predict_proba(scaled)[:, 1].astype(float).flatten()
        else:
            X_seq = scaled.reshape(X.shape[0], 1, N_FEATURES)
            probs = self._model.predict(X_seq, verbose=0).flatten()
        preds  = (probs >= thr).astype(int)
        return probs, preds

    def reset_history(self) -> None:
        """Reset the rolling sequence buffer (call between process episodes)."""
        self._history.clear()


# ---------------------------------------------------------------------------
# Output row builder
# ---------------------------------------------------------------------------

def build_prediction_row(
    timestamp: str,
    process_name: str,
    result: Dict,
    source: str = "HONEYPOT",
) -> Dict:
    return {
        "timestamp":    timestamp,
        "process_name": process_name,
        "prediction":   result["prediction"],
        "confidence":   result["confidence"],
        "threat_level": result["threat_level"],
        "source":       source,
    }


PREDICTIONS_HEADER = [
    "timestamp", "process_name", "prediction",
    "confidence", "threat_level", "source",
]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli_batch(args) -> None:
    import pandas as pd

    df = pd.read_csv(args.input)
    print(f"[PREDICT] Loaded {len(df)} rows from {args.input}")

    det = RansomwareDetector(threshold=args.threshold or load_threshold())
    probs, preds = det.predict_dataframe(df, threshold=args.threshold)

    print(f"[PREDICT] Threshold : {det.threshold}")
    print(f"[PREDICT] Benign    : {int((preds == 0).sum())}")
    print(f"[PREDICT] Ransomware: {int((preds == 1).sum())}")

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_df = df.copy()
        out_df["prob_ransomware"]  = probs
        out_df["predicted_label"]  = preds
        out_df["threat_level"]     = [classify_threat(p) for p in probs]
        out_df.to_csv(out_path, index=False)
        print(f"[PREDICT] Wrote results -> {out_path}")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="LSTM Ransomware Batch Predictor")
    p.add_argument("--input",     "-i", required=True,
                   help="CSV file of behavioral features")
    p.add_argument("--output",    "-o", default=None,
                   help="path to write predictions CSV")
    p.add_argument("--threshold", "-t", type=float, default=None,
                   help="decision threshold (default: loaded from models/threshold.txt)")
    p.add_argument("--model",           default=None,
                   help="override model path")
    p.add_argument("--scaler",          default=None,
                   help="override scaler path")
    return p


def main() -> None:
    args = _build_parser().parse_args()
    _cli_batch(args)


if __name__ == "__main__":
    main()
