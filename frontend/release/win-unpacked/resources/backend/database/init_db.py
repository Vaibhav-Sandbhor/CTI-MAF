"""Database initialization for CyberSIEM."""
import logging
from database.db_manager import get_db

logger = logging.getLogger(__name__)


def init_database():
    """Create all required tables in the database."""
    try:
        with get_db() as conn:
            cursor = conn.cursor()

            # Create scan_sessions table (with user_id for session-based storage)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    status TEXT DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Add user_id column if table already exists without it
            try:
                cursor.execute("ALTER TABLE scan_sessions ADD COLUMN user_id INTEGER")
                logger.info("✅ Added user_id column to scan_sessions")
            except Exception:
                pass  # Column already exists

            # Create session_snapshots table for final dashboard state storage
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS session_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    snapshot_data TEXT NOT NULL,
                    snapshot_type TEXT DEFAULT 'FINAL',
                    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
                )
            """)

            # Create timeline_snapshots table for optional periodic snapshots (max 5)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS timeline_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    snapshot_data TEXT NOT NULL,
                    sequence_number INTEGER NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
                )
            """)

            # Create threat_events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    module TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
                )
            """)

            # Create scan_metrics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    ransomware_count INTEGER DEFAULT 0,
                    portscan_count INTEGER DEFAULT 0,
                    honeypot_hits INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
                )
            """)

            # Create indexes for faster queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_events_session ON threat_events(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_events_timestamp ON threat_events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_metrics_session ON scan_metrics(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_metrics_timestamp ON scan_metrics(timestamp)")

            # Indexes for session-based storage tables
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_sessions_user ON scan_sessions(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_session_snapshots_session ON session_snapshots(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_timeline_snapshots_session ON timeline_snapshots(session_id)")

            logger.info("✅ Database tables initialized successfully")

    except Exception as e:
        logger.error(f"❌ Error initializing database: {e}")
        raise
