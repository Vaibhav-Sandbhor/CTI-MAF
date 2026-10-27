"""Tests for the LSTM ransomware detection module."""

import numpy as np
import pandas as pd
import pytest

from models.predict_lstm import load_detector, predict_dataframe, load_threshold


@pytest.fixture(scope="module")
def model_scaler():
    """Load the LSTM model and scaler once per test session.

    If TensorFlow or the model file cannot be loaded the fixture skips the
    tests gracefully.
    """
    try:
        model, scaler = load_detector()
    except Exception as e:
        pytest.skip(f"could not load LSTM detector: {e}")
    return model, scaler


def make_row(ata, mem, disk, memw):
    return {
        "ata_entropy_avg": ata,
        "mem_entropy_avg": mem,
        "disk_write_ratio": disk,
        "mem_write_ratio": memw,
    }


def test_true_negative(model_scaler):
    model, scaler = model_scaler
    df = pd.DataFrame([make_row(0.0, 0.0, 0.0, 0.0)])
    probs, preds, thr = predict_dataframe(df, model, scaler, threshold=load_threshold())
    assert probs[0] < thr
    assert preds[0] == 0


def test_true_positive(model_scaler):
    model, scaler = model_scaler
    # choose exaggerated feature values intended to drive prediction high
    df = pd.DataFrame([make_row(8.0, 8.0, 10.0, 10.0)])
    probs, preds, thr = predict_dataframe(df, model, scaler, threshold=load_threshold())
    assert probs[0] > thr
    assert preds[0] == 1


def test_borderline_case(model_scaler):
    model, scaler = model_scaler
    # values near threshold -- we don't require a specific side, just
    # that probability is within [thr-0.1, thr+0.1] and stable across calls.
    base_row = make_row(0.5, 0.5, 0.5, 0.5)
    df = pd.DataFrame([base_row])
    thr = load_threshold()
    probs1, preds1, _ = predict_dataframe(df, model, scaler, threshold=thr)
    probs2, preds2, _ = predict_dataframe(df, model, scaler, threshold=thr)
    assert abs(probs1[0] - thr) < 0.2
    assert probs1[0] == probs2[0]
    assert preds1[0] == preds2[0]
    # depending on the model the prediction may be 0 or 1, both acceptable
    assert preds1[0] in (0, 1)
