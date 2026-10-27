"""
honeypot_simulator.py
=====================
Module 1: Honeypot Deception Module

Operates in two modes:

  REAL mode  – creates decoy files on disk, uses watchdog to observe real
               filesystem events, logs what each process does to those files.

  SIMULATE mode – generates a synthetic honeypot_log.csv stream that mimics
                  realistic benign and ransomware activity for pipeline
                  testing and model validation without touching production files.

Output schema  (honeypot/honeypot_log.csv):
    timestamp, process_name, file_path, operation, entropy,
    extension_changed, write_count, rename_count, suspicious_score

Usage:
    # Simulation (default, safe for testing):
    python -m ransomware_module.honeypot.honeypot_simulator --mode simulate

    # Real filesystem monitoring (requires write access to decoy directory):
    python -m ransomware_module.honeypot.honeypot_simulator --mode real --decoy-dir ./decoys
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import random
import sys
import time
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------
_MODULE_ROOT = Path(__file__).resolve().parent.parent          # ransomware_module/
_HONEYPOT_DIR = _MODULE_ROOT / "honeypot"
LOG_PATH = _HONEYPOT_DIR / "honeypot_log.csv"

LOG_HEADER = [
    "timestamp", "process_name", "file_path", "operation",
    "entropy", "extension_changed", "write_count", "rename_count",
    "suspicious_score",
]

# ---------------------------------------------------------------------------
# Shannon entropy helper
# ---------------------------------------------------------------------------

def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy (bits) of a byte sequence."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def _file_entropy(path: Path) -> float:
    """Return entropy of file content, or 0.0 on error."""
    try:
        return _shannon_entropy(path.read_bytes())
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# Suspicious score calculation
# ---------------------------------------------------------------------------

def compute_suspicious_score(
    entropy: float,
    extension_changed: int,
    write_count: int,
    rename_count: int,
    operation: str,
) -> float:
    """Return [0,1] heuristic suspicion score for a single event."""
    score = 0.0
    # High entropy strongly implies ciphertext output
    if entropy > 7.5:
        score += 0.40
    elif entropy > 6.5:
        score += 0.25
    elif entropy > 5.0:
        score += 0.10
    # Extension mutations are a ransomware hallmark
    if extension_changed:
        score += 0.25
    # Rename activity
    if rename_count > 0:
        score += min(rename_count * 0.04, 0.15)
    # Bulk writes indicate encryption loop
    if write_count > 20:
        score += 0.20
    elif write_count > 10:
        score += 0.10
    elif write_count > 5:
        score += 0.05
    # DELETE on a honeypot is very suspicious (pre-encrypt delete)
    if operation == "DELETE":
        score += 0.15
    return round(min(score, 1.0), 4)


# ---------------------------------------------------------------------------
# Event dataclass
# ---------------------------------------------------------------------------

@dataclass
class HoneypotEvent:
    timestamp: str
    process_name: str
    file_path: str
    operation: str          # READ | WRITE | RENAME | DELETE | CREATE
    entropy: float
    extension_changed: int  # 0 or 1
    write_count: int
    rename_count: int
    suspicious_score: float


# ---------------------------------------------------------------------------
# CSV logger
# ---------------------------------------------------------------------------

class EventLogger:
    """Thread-safe CSV event logger."""

    def __init__(self, log_path: Path = LOG_PATH) -> None:
        self.log_path = log_path
        self._lock = threading.Lock()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        if not log_path.exists():
            with open(log_path, "w", newline="") as fh:
                csv.writer(fh).writerow(LOG_HEADER)

    def write(self, event: HoneypotEvent) -> None:
        with self._lock:
            with open(self.log_path, "a", newline="") as fh:
                csv.writer(fh).writerow([
                    event.timestamp, event.process_name, event.file_path,
                    event.operation, event.entropy, event.extension_changed,
                    event.write_count, event.rename_count, event.suspicious_score,
                ])

    def flush(self) -> None:
        pass  # writes are unbuffered


# ---------------------------------------------------------------------------
# Decoy file factory
# ---------------------------------------------------------------------------

_DECOY_NAMES = [
    "confidential_report.docx", "salary_database.xlsx",
    "backup_keys.txt", "private_notes.pdf", "employee_records.csv",
    "system_credentials.txt", "financial_summary.xlsx",
    "security_policy.docx", "project_timeline.pdf", "client_data.csv",
]

# Realistic benign-looking content for decoy files
_DECOY_CONTENT = (
    b"CONFIDENTIAL DOCUMENT\n"
    b"This file is monitored by CyberSIEM Honeypot Deception System.\n"
    b"Unauthorised access to this file is logged and will trigger alerts.\n"
    b"File integrity is continuously verified.\n"
)


def create_decoy_files(decoy_dir: Path, count: int = 10) -> List[Path]:
    """Create lightweight decoy files in *decoy_dir* and return their paths."""
    decoy_dir.mkdir(parents=True, exist_ok=True)
    created: List[Path] = []
    names = (_DECOY_NAMES * (count // len(_DECOY_NAMES) + 1))[:count]
    for name in names:
        p = decoy_dir / name
        p.write_bytes(_DECOY_CONTENT)
        created.append(p)
    print(f"[HONEYPOT] Created {len(created)} decoy files in {decoy_dir}")
    return created


# ---------------------------------------------------------------------------
# Real filesystem watcher (requires watchdog)
# ---------------------------------------------------------------------------

class _HoneypotEventHandler:
    """Watchdog event handler that logs filesystem events on decoy files."""

    def __init__(self, logger: EventLogger, decoy_paths: List[Path]) -> None:
        self.logger = logger
        self._decoy_set = {str(p.resolve()) for p in decoy_paths}
        # per-process accumulators  {process_name: {writes, renames}}
        self._accum: Dict[str, Dict] = {}

    def _is_decoy(self, path: str) -> bool:
        return path in self._decoy_set

    def _record(self, event_path: str, operation: str) -> None:
        if not self._is_decoy(event_path):
            return
        try:
            import psutil  # optional; graceful fallback
            proc_name = _get_accessor_process(event_path) or "unknown.exe"
        except ImportError:
            proc_name = "unknown.exe"

        p = Path(event_path)
        ext_orig = p.suffix.lower()
        entropy = _file_entropy(p) if operation in ("WRITE", "CREATE") else 0.0
        ext_changed = 1 if ext_orig not in {".txt", ".docx", ".xlsx", ".pdf", ".csv"} else 0

        acc = self._accum.setdefault(proc_name, {"write_count": 0, "rename_count": 0})
        if operation in ("WRITE", "CREATE"):
            acc["write_count"] += 1
        elif operation == "RENAME":
            acc["rename_count"] += 1
            ext_changed = 1

        score = compute_suspicious_score(
            entropy, ext_changed, acc["write_count"], acc["rename_count"], operation
        )
        event = HoneypotEvent(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            process_name=proc_name,
            file_path=event_path,
            operation=operation,
            entropy=entropy,
            extension_changed=ext_changed,
            write_count=acc["write_count"],
            rename_count=acc["rename_count"],
            suspicious_score=score,
        )
        self.logger.write(event)
        _print_event(event)

    # --- watchdog callback shims ---
    def on_modified(self, event):
        if not event.is_directory:
            self._record(event.src_path, "WRITE")

    def on_created(self, event):
        if not event.is_directory:
            self._record(event.src_path, "CREATE")

    def on_deleted(self, event):
        if not event.is_directory:
            self._record(event.src_path, "DELETE")

    def on_moved(self, event):
        if not event.is_directory:
            self._record(event.src_path, "RENAME")


def _get_accessor_process(path: str) -> Optional[str]:
    """Best-effort: return name of the process that last touched *path*."""
    try:
        import psutil
        for proc in psutil.process_iter(["name", "open_files"]):
            try:
                ofiles = proc.info.get("open_files") or []
                for of in ofiles:
                    if os.path.normcase(of.path) == os.path.normcase(path):
                        return proc.info["name"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except ImportError:
        pass
    return None


def _print_event(event: HoneypotEvent) -> None:
    level = "CRITICAL" if event.suspicious_score > 0.7 else (
        "WARNING" if event.suspicious_score > 0.4 else "INFO"
    )
    print(
        f"[{level}] {event.timestamp} | {event.process_name:20s} | "
        f"{event.operation:8s} | entropy={event.entropy:.2f} | "
        f"score={event.suspicious_score:.2f} | {Path(event.file_path).name}"
    )


# ---------------------------------------------------------------------------
# Real monitoring mode
# ---------------------------------------------------------------------------

def run_real_monitor(decoy_dir: Path, logger: EventLogger) -> None:
    """
    Deploy real decoy files and watch them using watchdog.
    Logs any filesystem interaction to honeypot_log.csv.
    Blocks indefinitely – press Ctrl-C to stop.
    """
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        print("[ERROR] watchdog not installed. Run: pip install watchdog")
        sys.exit(1)

    decoy_paths = create_decoy_files(decoy_dir, count=10)

    class _Adapter(FileSystemEventHandler):
        def __init__(self, handler: _HoneypotEventHandler):
            self._h = handler

        def on_modified(self, event):  self._h.on_modified(event)
        def on_created(self, event):   self._h.on_created(event)
        def on_deleted(self, event):   self._h.on_deleted(event)
        def on_moved(self, event):     self._h.on_moved(event)

    handler = _HoneypotEventHandler(logger, decoy_paths)
    adapter = _Adapter(handler)

    observer = Observer()
    observer.schedule(adapter, str(decoy_dir), recursive=False)
    observer.start()

    print(f"[HONEYPOT] Real monitor active on {decoy_dir}")
    print(f"[HONEYPOT] Logging to {logger.log_path}")
    print("[HONEYPOT] Press Ctrl-C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[HONEYPOT] Stopping monitor…")
    finally:
        observer.stop()
        observer.join()


# ---------------------------------------------------------------------------
# Simulation mode
# ---------------------------------------------------------------------------

# Benign process profiles
_BENIGN_PROCESSES = [
    "explorer.exe", "winword.exe", "excel.exe", "notepad.exe",
    "acrobat.exe", "chrome.exe", "outlook.exe", "teams.exe",
]

# Ransomware-like process names (realistic but entirely fictional)
_RANSOM_PROCESSES = [
    "svc_update.exe", "taskhost.exe", "conhost32.exe",
    "syswow64helper.exe", "wscript_helper.exe",
]

_DECOY_FILES = [f"honeypot/decoys/{n}" for n in _DECOY_NAMES]


def _simulate_benign_event(logger: EventLogger) -> None:
    proc = random.choice(_BENIGN_PROCESSES)
    fpath = random.choice(_DECOY_FILES)
    op = random.choice(["READ", "READ", "READ", "WRITE"])
    entropy = round(random.uniform(0.5, 3.5), 4)
    ext_changed = 0
    write_count = random.randint(1, 3) if op == "WRITE" else 0
    rename_count = 0
    score = compute_suspicious_score(entropy, ext_changed, write_count, rename_count, op)
    event = HoneypotEvent(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        process_name=proc,
        file_path=fpath,
        operation=op,
        entropy=entropy,
        extension_changed=ext_changed,
        write_count=write_count,
        rename_count=rename_count,
        suspicious_score=score,
    )
    logger.write(event)
    _print_event(event)


def _simulate_ransomware_event(logger: EventLogger, burst_size: int = 5) -> None:
    """Simulate a ransomware encryption burst across multiple decoy files."""
    proc = random.choice(_RANSOM_PROCESSES)
    write_acc = 0
    rename_acc = 0
    targets = random.sample(_DECOY_FILES, min(burst_size, len(_DECOY_FILES)))

    for fpath in targets:
        op = random.choices(
            ["WRITE", "RENAME", "DELETE"],
            weights=[0.60, 0.30, 0.10],
        )[0]
        # High-entropy writes simulate ciphertext output
        entropy = round(random.uniform(7.0, 7.99), 4) if op == "WRITE" else round(
            random.uniform(0.0, 1.0), 4
        )
        ext_changed = 1 if op in ("RENAME", "WRITE") else 0
        if op == "WRITE":
            write_acc += random.randint(3, 8)
        elif op == "RENAME":
            rename_acc += 1

        score = compute_suspicious_score(entropy, ext_changed, write_acc, rename_acc, op)
        event = HoneypotEvent(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            process_name=proc,
            file_path=fpath,
            operation=op,
            entropy=entropy,
            extension_changed=ext_changed,
            write_count=write_acc,
            rename_count=rename_acc,
            suspicious_score=score,
        )
        logger.write(event)
        _print_event(event)
        time.sleep(random.uniform(0.05, 0.25))  # burst timing


def run_simulation(
    n_benign: int = 50,
    n_ransom_bursts: int = 5,
    logger: Optional[EventLogger] = None,
    log_path: Path = LOG_PATH,
    seed: Optional[int] = None,
) -> int:
    """
    Generate a synthetic honeypot log with *n_benign* individual benign events
    and *n_ransom_bursts* ransomware burst sequences.

    Returns the total number of events written.
    """
    if seed is not None:
        random.seed(seed)

    logger = logger or EventLogger(log_path)

    print(f"[HONEYPOT-SIM] Starting simulation -> {log_path}")
    print(f"[HONEYPOT-SIM] Benign events: {n_benign}  |  Ransomware bursts: {n_ransom_bursts}\n")

    total = 0
    # Interleave benign activity with occasional ransomware bursts
    benign_per_burst = max(1, n_benign // (n_ransom_bursts + 1))
    burst_count = 0

    for i in range(n_benign):
        _simulate_benign_event(logger)
        total += 1
        time.sleep(random.uniform(0.02, 0.15))

        # Inject ransomware burst every `benign_per_burst` benign events
        if (i + 1) % benign_per_burst == 0 and burst_count < n_ransom_bursts:
            burst_size = random.randint(4, 8)
            print(f"\n[HONEYPOT-SIM] !!! RANSOMWARE BURST {burst_count+1} — "
                  f"targeting {burst_size} decoy files\n")
            _simulate_ransomware_event(logger, burst_size=burst_size)
            total += burst_size
            burst_count += 1

    # Any remaining bursts
    while burst_count < n_ransom_bursts:
        burst_size = random.randint(4, 8)
        print(f"\n[HONEYPOT-SIM] !!! RANSOMWARE BURST {burst_count+1}\n")
        _simulate_ransomware_event(logger, burst_size=burst_size)
        total += burst_size
        burst_count += 1

    print(f"\n[HONEYPOT-SIM] Simulation complete. {total} events written to {log_path}")
    return total


# ---------------------------------------------------------------------------
# HoneypotSimulator public API
# ---------------------------------------------------------------------------

class HoneypotSimulator:
    """
    Main interface for the Honeypot Deception Module.

    Parameters
    ----------
    mode : str
        'simulate' – synthetic log generation (default; safe for CI/testing)
        'real'     – live filesystem monitoring with decoy files
    log_path : Path
        Destination CSV path for honeypot event log.
    decoy_dir : Path
        Directory to deploy decoy files in real mode.
    """

    MODES = ("simulate", "real")

    def __init__(
        self,
        mode: str = "simulate",
        log_path: Path = LOG_PATH,
        decoy_dir: Optional[Path] = None,
    ) -> None:
        if mode not in self.MODES:
            raise ValueError(f"mode must be one of {self.MODES}")
        self.mode = mode
        self.log_path = Path(log_path)
        self.decoy_dir = Path(decoy_dir) if decoy_dir else (
            _MODULE_ROOT / "honeypot" / "decoys"
        )
        self.logger = EventLogger(self.log_path)

    def run(
        self,
        n_benign: int = 50,
        n_ransom_bursts: int = 5,
        seed: Optional[int] = None,
    ) -> None:
        """
        Start the honeypot.

        In simulate mode, generates *n_benign* benign events and
        *n_ransom_bursts* ransomware bursts then exits.

        In real mode, deploys decoy files and blocks indefinitely
        (ignores n_benign / n_ransom_bursts arguments).
        """
        if self.mode == "simulate":
            run_simulation(
                n_benign=n_benign,
                n_ransom_bursts=n_ransom_bursts,
                logger=self.logger,
                log_path=self.log_path,
                seed=seed,
            )
        else:
            run_real_monitor(self.decoy_dir, self.logger)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="CyberSIEM Honeypot Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--mode", choices=["simulate", "real"], default="simulate",
        help="simulate: generate synthetic log | real: monitor live filesystem",
    )
    p.add_argument(
        "--decoy-dir", type=Path,
        default=_MODULE_ROOT / "honeypot" / "decoys",
        help="directory for decoy files (real mode only)",
    )
    p.add_argument(
        "--log-path", type=Path, default=LOG_PATH,
        help="output CSV path for honeypot events",
    )
    p.add_argument(
        "--benign", type=int, default=60,
        help="number of benign events to simulate (simulate mode)",
    )
    p.add_argument(
        "--bursts", type=int, default=6,
        help="number of ransomware bursts to inject (simulate mode)",
    )
    p.add_argument(
        "--seed", type=int, default=None,
        help="random seed for reproducibility",
    )
    return p


def main() -> None:
    args = _build_parser().parse_args()
    sim = HoneypotSimulator(
        mode=args.mode,
        log_path=args.log_path,
        decoy_dir=args.decoy_dir,
    )
    sim.run(n_benign=args.benign, n_ransom_bursts=args.bursts, seed=args.seed)


if __name__ == "__main__":
    main()
