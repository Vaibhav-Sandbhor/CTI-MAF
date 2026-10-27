"""Session management for CyberSIEM scan sessions."""
import logging
from datetime import datetime, timezone
from database.db_manager import execute_update, execute_query

logger = logging.getLogger(__name__)


def start_session():
    """Start a new scan session and return the session ID."""
    try:
        session_id = execute_update(
            "INSERT INTO scan_sessions (status) VALUES ('ACTIVE')"
        )
        logger.info(f"✅ Started scan session: {session_id}")
        return session_id
    except Exception as e:
        logger.error(f"❌ Error starting session: {e}")
        raise


def end_session(session_id):
    """End a scan session."""
    try:
        utc_time = datetime.now(timezone.utc).isoformat()
        execute_update(
            "UPDATE scan_sessions SET status = 'COMPLETED', end_time = ? WHERE id = ?",
            (utc_time, session_id)
        )
        logger.info(f"✅ Ended scan session: {session_id}")
    except Exception as e:
        logger.error(f"❌ Error ending session: {e}")
        raise


def get_current_session():
    """Get the most recent active session."""
    try:
        results = execute_query(
            "SELECT id FROM scan_sessions WHERE status = 'ACTIVE' ORDER BY start_time DESC LIMIT 1"
        )
        if results:
            return results[0]['id']
        return None
    except Exception as e:
        logger.error(f"❌ Error getting current session: {e}")
        return None


def get_session_info(session_id):
    """Get information about a specific session."""
    try:
        results = execute_query(
            "SELECT * FROM scan_sessions WHERE id = ?",
            (session_id,)
        )
        if results:
            return dict(results[0])
        return None
    except Exception as e:
        logger.error(f"❌ Error getting session info: {e}")
        return None
