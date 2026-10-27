"""Simple script to exercise the honeypot in a benign way.

This is not a unit test, but a reproducible helper you can run manually when
experimenting.  It creates a temporary directory, generates a few decoy files,
and then performs a single small modification separated by a delay longer than
the scoring window so that the suspicion score remains below threshold.

Usage::

    python tests/simulate_benign.py [--decoys 5] [--window 5]
"""

import argparse
import time
import tempfile
from pathlib import Path

from honeypot.decoy_generator import DecoyGenerator
from honeypot.scoring import evaluate


def main():
    parser = argparse.ArgumentParser(description="Run a benign honeypot simulation")
    parser.add_argument("--decoys", type=int, default=3, help="number of decoys to generate")
    parser.add_argument("--window", type=int, default=3, help="scoring window in seconds")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        print(f"[+] using temporary directory {base}")
        gen = DecoyGenerator(base, count=args.decoys)
        paths = gen.generate_decoys()
        print(f"[+] created {len(paths)} decoy files")

        # perform one small append to the first file
        with open(paths[0], "a") as f:
            f.write("benign change")
        print("[+] modified one file")

        # wait longer than the window so the event will be flushed separately
        time.sleep(args.window + 1)
        score, triggered = evaluate(1, 0.0, 0, 1.0 / args.window, args.decoys)
        print(f"score={score:.2f}, triggered={triggered}")
        print("[+] benign simulation complete")


if __name__ == "__main__":
    main()
