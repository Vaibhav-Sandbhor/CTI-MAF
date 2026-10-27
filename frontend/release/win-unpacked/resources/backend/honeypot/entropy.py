"""Utilities for computing Shannon entropy of byte sequences."""

import math


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of the supplied byte string.

    Based on the formula:
        H = -sum(p_i * log2(p_i))
    where p_i is the probability of byte value i.
    """
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
