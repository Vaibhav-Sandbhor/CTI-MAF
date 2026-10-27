"""Filesystem monitor that watches for changes to honeypot files."""

import time
from collections import defaultdict, deque
from threading import Lock

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


class HoneypotEventHandler(FileSystemEventHandler):
    """Handler that records events relevant to suspicion scoring."""

    def __init__(self):
        super().__init__()
        # store events as deque of (timestamp, event_type, path)
        self.events = deque()
        self.lock = Lock()

    def on_modified(self, event: FileSystemEvent):
        self._record("modified", event.src_path)

    def on_deleted(self, event: FileSystemEvent):
        self._record("deleted", event.src_path)

    def on_moved(self, event: FileSystemEvent):
        # treat move as rename
        self._record("renamed", event.dest_path)

    def _record(self, event_type: str, path: str):
        now = time.time()
        with self.lock:
            self.events.append((now, event_type, path))

    def flush_events(self, window: float) -> list[tuple]:
        """Return and remove events that occurred within the past *window* seconds.

        The previous implementation returned events *older* than the window, which
        made the scoring logic see zero recent activity.  The calling code (and
        the unit tests) expect a sliding window of recent events, so we change the
        behavior accordingly.

        Returns a list of (timestamp, event_type, path) tuples.
        """
        cutoff = time.time() - window
        recent = []
        with self.lock:
            # events are appended in chronological order; consume while they fall
            # inside the window.
            while self.events and self.events[0][0] >= cutoff:
                recent.append(self.events.popleft())
        return recent


class HoneypotMonitor:
    """Wrapper around watchdog Observer for the honeypot directory."""

    def __init__(self, path: str, handler: HoneypotEventHandler = None):
        self.path = path
        self.handler = handler or HoneypotEventHandler()
        self.observer = Observer()

    def start(self):
        self.observer.schedule(self.handler, self.path, recursive=True)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()
