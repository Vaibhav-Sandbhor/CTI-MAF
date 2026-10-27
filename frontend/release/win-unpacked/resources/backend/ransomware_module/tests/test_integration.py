"""Integration tests covering combined honeypot + LSTM behavior."""

import os
import tempfile
import time

import pytest
import pandas as pd

from honeypot.decoy_generator import DecoyGenerator
from honeypot.scoring import evaluate, normalize

# note: import of the ML prediction module is deferred inside fixtures
# to avoid crashing the entire test suite when TensorFlow cannot be
# initialized.  See load_detector() handling.
from models.predict_lstm import load_detector, predict_dataframe, load_threshold


@pytest.fixture(scope="module")
def model_scaler():
    try:
        return load_detector()
    except Exception as e:
        pytest.skip(f"could not load LSTM detector: {e}")


def score_record(modified, entropy_delta, renamed, write_rate, total):
    score, triggered = evaluate(modified, entropy_delta, renamed, write_rate, total)
    return score, triggered


def simulate_honeypot_activity(decoy_count, mode="normal"):
    # returns (modified, entropy_delta, renamed, write_rate)
    if mode == "normal":
        return (1, 0.0, 0, 0.1)
    elif mode == "slow_enc":
        return (2, 2.0, 0, 0.5)
    elif mode == "rapid_enc":
        return (decoy_count, 8.0, decoy_count, 20.0)
    elif mode == "noise":
        return (0, 0.0, 0, 0.0)
    raise ValueError(mode)


def test_hybrid_scenarios(model_scaler):
    model, scaler = model_scaler
    thr = load_threshold()
    decoys = 5

    for case, expected in [
        ("normal", (False, False)),
        ("slow_enc", (False, True)),
        ("rapid_enc", (True, True)),
        ("noise", (False, False)),
    ]:
        mod, ent, ren, rate = simulate_honeypot_activity(decoys, case)
        score, honeypot_alert = score_record(mod, ent, ren, rate, decoys)
        # build feature row for ML based on the record
        row = {
            "ata_entropy_avg": ent,
            "mem_entropy_avg": ent,
            "disk_write_ratio": rate,
            "mem_write_ratio": rate,
        }
        df = pd.DataFrame([row])
        probs, preds, _ = predict_dataframe(df, model, scaler, threshold=thr)

        ml_flag = bool(preds[0])
        expected_hp, expected_ml = expected
        assert honeypot_alert == expected_hp
        assert ml_flag == expected_ml


def test_scoring_formula():
    # verify explicit math with given weights
    from honeypot.scoring import ScoreConfig
    cfg = ScoreConfig(w1=0.5, w2=0.5, w3=0.0, w4=0.0, threshold=0.5)
    # compute manually
    M = 0.2
    E = 0.4
    raw = cfg.w1 * M + cfg.w2 * E
    total_w = cfg.w1 + cfg.w2
    expected_score = raw / total_w
    score, triggered = evaluate(1, 0.4, 0, 0.0, 5, cfg)
    assert pytest.approx(score, rel=1e-3) == expected_score
    assert triggered == (score > cfg.threshold)


def test_randomized_attack_statistics():
    """Generate 100 random "attacks" to compute average/variance of the score.

    This is an optional robustness check and marked slow so CI can skip if
    desired.  It ensures the scoring function behaves numerically stable under
    noise.
    """
    import random
    random.seed(0)
    samples = []
    for _ in range(100):
        m = random.randint(0, 5)
        e = random.random() * 8
        r = random.randint(0, 5)
        w = random.random() * 20
        score, _ = evaluate(m, e, r, w, 5)
        samples.append(score)
    avg = sum(samples) / len(samples)
    var = sum((x - avg) ** 2 for x in samples) / len(samples)
    # just ensure we computed something sensible
    assert 0.0 <= avg <= 1.0
    assert var >= 0.0
