"""
feature_extractor.py
====================
General behavioral feature extraction utilities.

Defines the BEHAVIORAL_FEATURES schema used throughout the ransomware_module
pipeline and provides helper functions for feature normalization, validation,
and sequence preparation.

Feature schema (10 numeric features):
    cpu_usage          – CPU % of the process (0–100)
    memory_usage       – Working-set MB
    file_read_count    – Files read in the observation window
    file_write_count   – Files written / overwritten
    file_delete_count  – Files deleted
    registry_change_count – Registry key writes / deletes
    network_connections   – Active outbound TCP connections
    entropy            – Mean Shannon entropy of modified files (0–8)
    extension_change   – 1 if any extension mutation was observed, else 0
    process_spawn_count– Child processes spawned
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence
import math

import numpy as np

# ---------------------------------------------------------------------------
# Feature schema constants
# ---------------------------------------------------------------------------

BEHAVIORAL_FEATURES: List[str] = [
    "cpu_usage",
    "memory_usage",
    "file_read_count",
    "file_write_count",
    "file_delete_count",
    "registry_change_count",
    "network_connections",
    "entropy",
    "extension_change",
    "process_spawn_count",
]

N_FEATURES = len(BEHAVIORAL_FEATURES)   # 10

# Default thresholds used by the prediction layer
SIGMOID_THRESHOLD_DEFAULT = 0.5
SIGMOID_THRESHOLD_PRODUCTION = 0.7

# Threat classification boundaries
THREAT_LEVELS = {
    "BENIGN":     (0.0,  0.50),
    "SUSPICIOUS": (0.50, 0.70),
    "RANSOMWARE": (0.70, 1.01),
}

# ---------------------------------------------------------------------------
# Feature validation
# ---------------------------------------------------------------------------


def validate_feature_row(row: Dict) -> Dict:
    """
    Coerce and clip a feature dictionary into valid numeric ranges.

    Returns a new dict with all BEHAVIORAL_FEATURES present as floats.
    Missing columns default to 0.
    """
    out: Dict[str, float] = {}
    for feat in BEHAVIORAL_FEATURES:
        try:
            val = float(row.get(feat, 0) or 0)
        except (TypeError, ValueError):
            val = 0.0
        out[feat] = val

    # Clip plausible bounds
    out["cpu_usage"]           = max(0.0, min(100.0, out["cpu_usage"]))
    out["memory_usage"]        = max(0.0, out["memory_usage"])
    out["entropy"]             = max(0.0, min(8.0, out["entropy"]))
    out["extension_change"]    = float(bool(out["extension_change"]))
    return out


def feature_dict_to_array(row: Dict) -> np.ndarray:
    """Return a 1-D float32 array of shape (N_FEATURES,) from a feature dict."""
    d = validate_feature_row(row)
    return np.array([d[f] for f in BEHAVIORAL_FEATURES], dtype=np.float32)


def feature_rows_to_matrix(rows: List[Dict]) -> np.ndarray:
    """Return (n_samples, N_FEATURES) float32 matrix from a list of dicts."""
    return np.stack([feature_dict_to_array(r) for r in rows], axis=0)


# ---------------------------------------------------------------------------
# Threat level classification
# ---------------------------------------------------------------------------


def classify_threat(probability: float) -> str:
    """Map a probability score [0,1] to a threat label."""
    if probability >= THREAT_LEVELS["RANSOMWARE"][0]:
        return "RANSOMWARE"
    if probability >= THREAT_LEVELS["SUSPICIOUS"][0]:
        return "SUSPICIOUS"
    return "BENIGN"


def threat_to_alert_level(threat: str) -> str:
    """Map a threat label to a SOC alert severity level."""
    return {
        "RANSOMWARE": "CRITICAL",
        "SUSPICIOUS": "WARNING",
        "BENIGN":     "INFO",
    }.get(threat, "INFO")


# ---------------------------------------------------------------------------
# Sequence builder for LSTM
# ---------------------------------------------------------------------------


def build_sequences(
    X: np.ndarray,
    seq_len: int = 5,
    y: Optional[np.ndarray] = None,
):
    """
    Convert a (n_samples, n_features) matrix into overlapping LSTM sequences.

    Returns:
        X_seq : ndarray of shape (n_samples - seq_len + 1, seq_len, n_features)
        y_seq : ndarray of shape (n_samples - seq_len + 1,) or None
    """
    n = len(X)
    if n < seq_len:
        # Pad with zeros at the front
        pad = np.zeros((seq_len - n, X.shape[1]), dtype=X.dtype)
        X = np.vstack([pad, X])
        n = seq_len

    X_seq = np.stack([X[i: i + seq_len] for i in range(n - seq_len + 1)], axis=0)
    if y is not None:
        y_seq = y[seq_len - 1:]
        return X_seq, y_seq
    return X_seq, None


# ---------------------------------------------------------------------------
# Simple entropy utilities
# ---------------------------------------------------------------------------


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy (bits per symbol) of a byte string."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    H = 0.0
    for cnt in freq.values():
        p = cnt / length
        H -= p * math.log2(p)
    return H
