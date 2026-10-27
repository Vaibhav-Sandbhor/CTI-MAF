"""Suspicion scoring logic for honeypot events."""

from dataclasses import dataclass
from typing import List


@dataclass
class ScoreConfig:
    # default weights have been tuned to de-emphasize raw modification
    # ratio and write rate; entropy and rename activity drive the score more
    # strongly.  This reduces the benign mean score while preserving high
    # detection against rapid, high-entropy events.
    w1: float = 0.5   # modified ratio weight (reduced)
    w2: float = 1.0   # entropy delta weight (strong)
    w3: float = 1.0   # rename count weight (strong)
    w4: float = 0.5   # write rate weight (reduced)
    threshold: float = 0.7


def normalize(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    """Clamp/scale a value to [0,1]."""
    if maximum == minimum:
        return 0.0
    return max(min((value - minimum) / (maximum - minimum), 1.0), 0.0)


def compute_score(
    modified: int,
    entropy_delta: float,
    renamed: int,
    write_rate: float,
    total_decoys: int,
    config: ScoreConfig = ScoreConfig(),
) -> float:
    """Compute a normalized suspicion score according to design spec.

    """
    m_frac = modified / total_decoys if total_decoys > 0 else 0.0
    w_rate = normalize(write_rate, 0, 100)  # assume 100 writes/sec as cap

    raw = (
        config.w1 * m_frac
        + config.w2 * entropy_delta
        + config.w3 * renamed
        + config.w4 * w_rate
    )
    # naive normalization -- divide by sum of weights
    total_w = config.w1 + config.w2 + config.w3 + config.w4
    if total_w <= 0:
        return 0.0
    score = raw / total_w
    return normalize(score)


def evaluate(
    modified: int,
    entropy_delta: float,
    renamed: int,
    write_rate: float,
    total_decoys: int,
    config: ScoreConfig | None = None,
):
    """Return (score, triggered_bool).

    ``config`` may be ``None`` in which case the default ``ScoreConfig`` is
    created lazily.  The original implementation used a default argument
    instance which meant callers could pass ``None`` and crash.
    """
    if config is None:
        config = ScoreConfig()
    score = compute_score(modified, entropy_delta, renamed, write_rate, total_decoys, config)
    return score, score > config.threshold
