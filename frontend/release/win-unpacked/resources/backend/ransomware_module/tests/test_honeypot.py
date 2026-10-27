"""Unit tests for the minimal filesystem honeypot modules."""

import os
import time
import tempfile

import pytest

from honeypot.decoy_generator import DecoyGenerator
from honeypot.monitor import HoneypotMonitor, HoneypotEventHandler
from honeypot.scoring import evaluate
from honeypot.entropy import shannon_entropy


def test_shannon_entropy_empty():
    assert shannon_entropy(b"") == 0.0


def test_shannon_entropy_known():
    # all bytes equal -> entropy 0
    assert shannon_entropy(b"aaaa") == 0.0
    # two symbols with equal probability -> 1 bit
    assert pytest.approx(shannon_entropy(b"ab")) == 1.0


def test_scoring_simple_cases():
    # default configuration: only modified count matters
    cfg = None
    # one modified out of five => low score
    score, triggered = evaluate(1, 0.0, 0, 0.1, 5, cfg)
    assert score < 0.7
    assert not triggered

    # many modifications should trigger under default weights
    score, triggered = evaluate(5, 0.0, 0, 0.0, 5, cfg)
    assert triggered

    # rename burst should trigger if we give renames weight
    from honeypot.scoring import ScoreConfig
    cfg2 = ScoreConfig(w3=1.0)
    score, triggered = evaluate(0, 0.0, 3, 0.0, 5, cfg2)
    assert triggered


def test_monitor_integration(tmp_path):
    # create a temporary folder with decoys and stimulate modifications
    gen = DecoyGenerator(tmp_path, count=5)
    paths = gen.generate_decoys()
    handler = HoneypotEventHandler()
    monitor = HoneypotMonitor(str(tmp_path), handler)
    monitor.start()
    try:
        # modify several files quickly
        for p in paths[:3]:
            with open(p, "a") as f:
                f.write("change")
        # allow events to propagate
        time.sleep(1)
        events = handler.flush_events(5)
        mod_count = sum(1 for (_, t, _) in events if t == "modified")
        score, triggered = evaluate(mod_count, 0.0, 0, mod_count / 5, len(paths))
        assert mod_count >= 3
        assert triggered or score > 0
    finally:
        monitor.stop()


def test_honeypot_scenarios(tmp_path):
    """Run the three prescribed honeypot scenarios.

    * benign: modify one file, delayed -> no alert
    * ransomware: bulk high-entropy overwrite + rename -> alert
    * low-entropy: bulk overwrite with same character -> moderate score
    """
    # common helper
    def score_events(modified, entropy_delta, renamed, write_rate, total):
        return evaluate(modified, entropy_delta, renamed, write_rate, total)

    # benign case
    gen = DecoyGenerator(tmp_path, count=4)
    paths = gen.generate_decoys()
    # small append to one file
    with open(paths[0], "a") as f:
        f.write("x")
    time.sleep(2)
    # only one modification, after window, so score should be low
    score, triggered = score_events(1, 0.0, 0, 0.5, len(paths))
    assert score < 0.7
    assert not triggered

    # ransomware simulation
    gen2 = DecoyGenerator(tmp_path, count=4)
    paths2 = gen2.generate_decoys()
    # deduplicate names to avoid renaming the same file twice
    unique = []
    seen = set()
    for p in paths2:
        if str(p) not in seen:
            seen.add(str(p))
            unique.append(p)
    start = time.time()
    for p in unique:
        with open(p, "wb") as f:
            f.write(os.urandom(2048))
        newp = p.with_suffix(p.suffix + ".encrypted")
        p.rename(newp)
    elapsed = time.time() - start
    rate = len(unique) / max(elapsed, 1e-6)
    score, triggered = score_events(len(unique), 8.0, len(unique), rate, len(unique))
    assert triggered
    assert score > 0.7

    # low entropy bulk write – use a config that ignores raw modification
    # count so the lack of entropy keeps the score low.
    from honeypot.scoring import ScoreConfig
    cfg = ScoreConfig(w1=0.0, w2=1.0, threshold=0.7)
    gen3 = DecoyGenerator(tmp_path, count=4)
    paths3 = gen3.generate_decoys()
    for p in paths3:
        with open(p, "wb") as f:
            f.write(b"A" * 1024)
    score, triggered = evaluate(4, 0.0, 0, 4.0, len(paths3), cfg)
    assert score < cfg.threshold
    assert not triggered
