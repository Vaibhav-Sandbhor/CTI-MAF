"""Script that mimics rapid ransomware activity against the honeypot.

Generates decoy files and then overwrites every file with random bytes,
renaming to ".encrypted" in a tight loop.  Prints the resulting suspicion score
and whether an alert would have fired.

Usage::

    python tests/simulate_ransomware.py [--decoys 5] [--window 2]
"""

import argparse
import os
import random
import time
import tempfile
from pathlib import Path

from honeypot.decoy_generator import DecoyGenerator
from honeypot.scoring import evaluate


random.seed(42)


def high_entropy_bytes(kb: int) -> bytes:
    return os.urandom(kb * 1024)


def main():
    parser = argparse.ArgumentParser(description="Run a ransomware-like honeypot simulation")
    parser.add_argument("--decoys", type=int, default=5)
    parser.add_argument("--window", type=int, default=2)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        gen = DecoyGenerator(base, count=args.decoys)
        paths = gen.generate_decoys()

        start = time.time()
        for p in paths:
            # overwrite with high-entropy content
            with open(p, "wb") as f:
                f.write(high_entropy_bytes(4))
            # rename immediately
            p.rename(p.with_suffix(p.suffix + ".encrypted"))
        elapsed = time.time() - start

        write_rate = args.decoys / max(elapsed, 1e-6)
        score, triggered = evaluate(args.decoys, 8.0, args.decoys, write_rate, args.decoys)
        print(f"score={score:.2f}, triggered={triggered}")
        print("[+] ransomware simulation complete")


if __name__ == "__main__":
    main()
