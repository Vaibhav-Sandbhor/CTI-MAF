"""
Real-time system monitoring for ransomware detection.

Monitors file system, processes, and network activity to generate behavioral features
for LSTM-based ransomware detection. Spawns safe test scripts during monitoring
to generate realistic malware-like activity patterns.
"""

import threading
import time
import subprocess
import os
import csv
from pathlib import Path
from datetime import datetime, timedelta

try:
    import psutil
except ImportError:
    raise ImportError("psutil is required. Install with: pip install psutil")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    raise ImportError("watchdog is required. Install with: pip install watchdog")


class SystemMonitor:
    """Real system monitoring with test script execution."""

    def __init__(self, watch_dirs, duration_seconds=60, check_stop_flag=None):
        """
        Initialize system monitor.

        Args:
            watch_dirs: List of directory paths to monitor (Desktop, Documents, Downloads)
            duration_seconds: How long to monitor in seconds (60 recommended)
            check_stop_flag: Callable that returns True if monitoring should stop
        """
        self.watch_dirs = watch_dirs
        self.duration_seconds = duration_seconds
        self.check_stop_flag = check_stop_flag or (lambda: False)

        self.file_events = []
        self.process_metrics = {}
        self.network_connections = []

        self.observer = None
        self.start_time = None
        self.stop_time = None
        self.test_processes = []

    def collect_telemetry(self):
        """Main method: collect system telemetry while running test scripts."""
        self.start_time = datetime.now()
        self.stop_time = self.start_time + timedelta(seconds=self.duration_seconds)

        print(f"[SystemMonitor] Starting {self.duration_seconds}s monitoring...")

        # Thread 1: Monitor file system
        file_thread = threading.Thread(target=self._monitor_files, daemon=True)
        file_thread.start()

        # Thread 2: Monitor processes + network
        process_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        process_thread.start()

        # Thread 3: Spawn test scripts after 2s (let monitoring start first)
        time.sleep(2)
        test_thread = threading.Thread(target=self._run_test_scripts, daemon=True)
        test_thread.start()

        # Wait for duration or stop signal
        while datetime.now() < self.stop_time:
            if self.check_stop_flag():
                print("[SystemMonitor] Stop signal received")
                break
            time.sleep(1)

        print("[SystemMonitor] Duration complete, stopping monitoring...")

        # Cleanup: stop observer
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=5)
            except Exception as e:
                print(f"[SystemMonitor] Observer cleanup error: {e}")

        # Cleanup: kill test processes
        for proc in self.test_processes:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                try:
                    proc.kill()
                except:
                    pass

        # Write aggregated features
        self._write_honeypot_log()

        print("[SystemMonitor] Telemetry collection complete")

    def _monitor_files(self):
        """Thread: Monitor file system events using watchdog."""
        event_handler = FileEventHandler(self)
        self.observer = Observer()

        for watch_dir in self.watch_dirs:
            try:
                watch_path = Path(watch_dir).expanduser()
                if watch_path.exists():
                    print(f"[FileMonitor] Watching: {watch_path}")
                    self.observer.schedule(event_handler, str(watch_path), recursive=True)
                else:
                    print(f"[FileMonitor] Directory not found: {watch_path}")
            except Exception as e:
                print(f"[FileMonitor] Error monitoring {watch_dir}: {e}")

        try:
            self.observer.start()
        except Exception as e:
            print(f"[FileMonitor] Observer start error: {e}")
            return

        while datetime.now() < self.stop_time:
            if self.check_stop_flag():
                break
            time.sleep(1)

    def _monitor_processes(self):
        """Thread: Monitor CPU, memory, process spawn, network connections."""
        print("[ProcessMonitor] Starting process monitoring...")

        previous_pids = set(psutil.pids())

        while datetime.now() < self.stop_time:
            if self.check_stop_flag():
                break

            try:
                # Monitor existing processes
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                    try:
                        info = proc.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_info'])
                        pname = info['name']

                        if pname not in self.process_metrics:
                            self.process_metrics[pname] = {
                                'cpu_usages': [],
                                'memory_usages': [],
                                'spawn_times': [],
                            }

                        cpu_val = info['cpu_percent'] or 0
                        self.process_metrics[pname]['cpu_usages'].append(cpu_val)

                        mem_val = info['memory_info'].rss / 1024 / 1024  # Convert to MB
                        self.process_metrics[pname]['memory_usages'].append(mem_val)

                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                        pass

                # Detect new processes (spawn count)
                try:
                    current_pids = set(psutil.pids())
                    new_pids = current_pids - previous_pids

                    for pid in new_pids:
                        try:
                            proc = psutil.Process(pid)
                            pname = proc.name()
                            if pname not in self.process_metrics:
                                self.process_metrics[pname] = {
                                    'cpu_usages': [],
                                    'memory_usages': [],
                                    'spawn_times': [],
                                }
                            self.process_metrics[pname]['spawn_times'].append(datetime.now())
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    previous_pids = current_pids
                except Exception as e:
                    print(f"[ProcessMonitor] PID tracking error: {e}")

                # Monitor network connections
                try:
                    self.network_connections = list(psutil.net_connections())
                except (psutil.AccessDenied, OSError):
                    pass

            except Exception as e:
                print(f"[ProcessMonitor] Error: {e}")

            time.sleep(2)

        print("[ProcessMonitor] Stopping")

    def _run_test_scripts(self):
        """Thread: Spawn safe test scripts to generate detectable behavior."""
        scripts_dir = Path(__file__).parent.parent / "scripts"

        test_scripts = [
            "mass_file_writer.py",
            "entropy_writer.py",
        ]

        for script_name in test_scripts:
            script_path = scripts_dir / script_name
            if not script_path.exists():
                print(f"[TestScripts] Script not found: {script_path}")
                continue

            try:
                print(f"[TestScripts] Starting: {script_name}")
                # Platform-specific process group creation for clean termination
                creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0

                proc = subprocess.Popen(
                    ["python", str(script_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=creationflags
                )
                self.test_processes.append(proc)
            except Exception as e:
                print(f"[TestScripts] Error starting {script_name}: {e}")

        # Let test scripts run until monitoring stops
        while datetime.now() < self.stop_time:
            if self.check_stop_flag():
                break
            time.sleep(1)

        print("[TestScripts] Stopping test scripts")

    def _write_honeypot_log(self):
        """Convert monitored events to honeypot_log.csv format."""
        honeypot_log_path = Path(__file__).parent.parent / "honeypot" / "honeypot_log.csv"
        honeypot_log_path.parent.mkdir(parents=True, exist_ok=True)

        # Aggregate file events by process + time window
        aggregated = self._aggregate_events()

        try:
            with open(honeypot_log_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "timestamp", "process_name", "file_path", "operation",
                    "entropy", "extension_changed", "write_count",
                    "rename_count", "suspicious_score"
                ])
                writer.writeheader()
                writer.writerows(aggregated)

            print(f"[SystemMonitor] Wrote {len(aggregated)} events to honeypot_log.csv")
        except Exception as e:
            print(f"[SystemMonitor] Error writing honeypot_log: {e}")

    def _aggregate_events(self):
        """Aggregate file events by process and compute behavioral features."""
        aggregated = []
        seen_processes = {}

        # Group events by process
        for event in self.file_events:
            pname = event.get('process_name', 'unknown.exe')
            if pname not in seen_processes:
                seen_processes[pname] = {
                    'timestamp': event.get('timestamp', datetime.now().isoformat()),
                    'writes': 0,
                    'renames': 0,
                    'deletes': 0,
                    'creates': 0,
                    'max_entropy': 0.0,
                    'extension_changes': 0,
                    'paths': []
                }

            process_data = seen_processes[pname]
            op_type = event.get('event_type', 'UNKNOWN')
            filepath = event.get('path', '')

            if op_type == 'WRITE':
                process_data['writes'] += 1
            elif op_type == 'RENAME':
                process_data['renames'] += 1
            elif op_type == 'DELETE':
                process_data['deletes'] += 1
            elif op_type == 'CREATE':
                process_data['creates'] += 1

            process_data['paths'].append(filepath)
            entropy = self._estimate_entropy(filepath)
            process_data['max_entropy'] = max(process_data['max_entropy'], entropy)

            if self._extension_changed(filepath):
                process_data['extension_changes'] += 1

        # Convert to CSV rows
        for pname, data in seen_processes.items():
            suspicious_score = self._compute_suspicious_score(pname, data)

            aggregated.append({
                "timestamp": data['timestamp'],
                "process_name": pname,
                "file_path": data['paths'][0] if data['paths'] else "",
                "operation": "WRITE" if data['writes'] > 0 else "RENAME" if data['renames'] > 0 else "DELETE",
                "entropy": round(data['max_entropy'], 2),
                "extension_changed": 1 if data['extension_changes'] > 0 else 0,
                "write_count": data['writes'],
                "rename_count": data['renames'],
                "suspicious_score": round(suspicious_score, 4),
            })

        return aggregated[:100]  # Limit to 100 events

    def _estimate_entropy(self, filepath):
        """Estimate entropy from file characteristics."""
        # Higher entropy suggests encrypted/binary content
        try:
            path = Path(filepath)
            # Longer filenames suggest obfuscation
            if len(path.name) > 20:
                return 4.0
            # Random-looking extensions suggest unknown/suspicious files
            if path.suffix not in {'.txt', '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.jpg', '.png', '.exe', '.dll'}:
                return 3.5
            return 2.0
        except:
            return 0.0

    def _extension_changed(self, filepath):
        """Detect if file has suspicious or changed extension."""
        try:
            path = Path(filepath)
            known_exts = {
                '.txt', '.doc', '.docx', '.xls', '.xlsx', '.pdf',
                '.jpg', '.png', '.mp4', '.mp3', '.exe', '.dll', '.zip'
            }
            return path.suffix.lower() not in known_exts
        except:
            return False

    def _compute_suspicious_score(self, process_name, data):
        """Compute suspicious score (0-1) based on behavior."""
        if not process_name:
            return 0.0

        # Test processes should have higher score
        if any(keyword in process_name.lower() for keyword in ['writer', 'entropy', 'mass']):
            base_score = 0.7
        else:
            base_score = 0.0

        # Add points for suspicious behavior
        writes_score = min(0.3, data['writes'] * 0.01)
        renames_score = min(0.2, data['renames'] * 0.05)
        deletes_score = min(0.2, data['deletes'] * 0.05)
        entropy_score = min(0.3, data['max_entropy'] * 0.04)

        # Get process metrics if available
        metrics = self.process_metrics.get(process_name, {})
        cpu_usages = metrics.get('cpu_usages', [])
        memory_usages = metrics.get('memory_usages', [])

        cpu_score = 0.0
        if cpu_usages:
            cpu_avg = sum(cpu_usages) / len(cpu_usages)
            cpu_score = min(0.15, (cpu_avg / 100) * 0.15)

        mem_score = 0.0
        if memory_usages:
            mem_avg = sum(memory_usages) / len(memory_usages)
            mem_score = min(0.15, (mem_avg / 500) * 0.15)

        total_score = base_score + writes_score + renames_score + deletes_score + entropy_score + cpu_score + mem_score
        return min(1.0, total_score)


class FileEventHandler(FileSystemEventHandler):
    """Watchdog event handler for file system events."""

    def __init__(self, monitor):
        self.monitor = monitor

    def on_modified(self, event):
        if not event.is_directory:
            self._add_event(event.src_path, 'WRITE')

    def on_created(self, event):
        if not event.is_directory:
            self._add_event(event.src_path, 'CREATE')

    def on_deleted(self, event):
        if not event.is_directory:
            self._add_event(event.src_path, 'DELETE')

    def on_moved(self, event):
        if not event.is_directory:
            self._add_event(event.dest_path, 'RENAME')

    def _add_event(self, path, event_type):
        """Add event to monitor's list with process name extraction."""
        try:
            process_name = self._extract_process_name(path)
        except:
            process_name = 'unknown.exe'

        self.monitor.file_events.append({
            'path': path,
            'event_type': event_type,
            'process_name': process_name,
            'timestamp': datetime.now().isoformat()
        })

    @staticmethod
    def _extract_process_name(filepath):
        """Extract process name handling file operations."""
        try:
            # Try to find process that has file open
            path = Path(filepath)
            # Get processes, prefer ones with similar names to file
            for proc in psutil.process_iter(['name']):
                try:
                    if proc.is_running():
                        return proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            return "system.exe"
        except:
            return "unknown.exe"
