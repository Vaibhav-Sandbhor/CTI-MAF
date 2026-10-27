"""Entropy function validation tests."""

import pytest
from honeypot.entropy import shannon_entropy


def test_entropy_identical_bytes():
    assert shannon_entropy(b"AAAAAA") == pytest.approx(0.0)


def test_entropy_english_text():
    sample = b"The quick brown fox jumps over the lazy dog"
    h = shannon_entropy(sample)
    # English-like text should have entropy between 3 and 5 bits per byte
    assert 3.0 <= h <= 5.0


def test_entropy_random_bytes():
    import os
    data = os.urandom(1024)
    h = shannon_entropy(data)
    assert 7.0 <= h <= 8.0


def test_entropy_consistency():
    # calling twice on same data yields identical result
    b = b"abc123" * 10
    assert shannon_entropy(b) == shannon_entropy(b)
