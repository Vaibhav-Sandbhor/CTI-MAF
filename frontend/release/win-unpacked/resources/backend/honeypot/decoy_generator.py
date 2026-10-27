"""Create and manage realistic bait files for the filesystem honeypot."""

import os
import json
import random
import string
import time
from pathlib import Path


DEFAULT_EXTENSIONS = [".xlsx", ".csv", ".docx", ".zip"]
FILENAME_TEMPLATES = [
    "invoice_{year}_{q}.xlsx",
    "payroll_backup.csv",
    "confidential_report.docx",
    "project_archive.zip",
]


def _random_bytes(size: int) -> bytes:
    # generate high-entropy random content
    return os.urandom(size)


class DecoyGenerator:
    def __init__(self, base_path: Path, count: int = 10, refresh_interval: int = 60):
        """Initialize the decoy generator.

        Args:
            base_path: directory where decoys will be placed.
            count: number of files to generate.
            refresh_interval: seconds between refreshes (not yet used).
        """
        self.base_path = Path(base_path)
        self.count = count
        self.refresh_interval = refresh_interval
        self.metadata = []
        # ensure directory exists
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _pick_name(self) -> str:
        template = random.choice(FILENAME_TEMPLATES)
        year = time.localtime().tm_year
        q = ((time.localtime().tm_mon - 1) // 3) + 1
        return template.format(year=year, q=f"Q{q}")

    def _create_file(self, path: Path, size_kb: int = 16):
        # write some random bytes to inflate entropy
        with open(path, "wb") as f:
            f.write(_random_bytes(size_kb * 1024))

    def generate_decoys(self) -> list[Path]:
        """Create decoy files and return their paths.

        Existing files are refreshed (overwritten).
        Metadata about the generation is kept in memory.
        """
        paths = []
        self.metadata = []
        for i in range(self.count):
            name = self._pick_name()
            path = self.base_path / name
            self._create_file(path)
            paths.append(path)
            self.metadata.append({
                "path": str(path),
                "created": time.time(),
            })
        return paths

    def save_metadata(self, file: Path):
        """Optionally write metadata to JSON for persistence."""
        with open(file, "w") as f:
            json.dump(self.metadata, f, indent=2)
