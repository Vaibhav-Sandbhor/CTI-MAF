"""Metrics storage and retrieval for CyberSIEM."""
import logging
import json
from database.db_manager import execute_update, execute_query

logger = logging.getLogger(__name__)


def store_metrics(session_id, ransomware_count, portscan_count, honeypot_hits):
    """
    Store scan metrics after each scan cycle.

    Args:
        session_id: ID of the scan session
        ransomware_count: Number of ransomware threats detected
        portscan_count: Number of open ports detected
        honeypot_hits: Number of honeypot interactions
    """
    try:
        metric_id = execute_update(
            """INSERT INTO scan_metrics
               (session_id, ransomware_count, portscan_count, honeypot_hits)
               VALUES (?, ?, ?, ?)""",
            (session_id, ransomware_count, portscan_count, honeypot_hits)
        )
        logger.info(f"📊 Stored metrics: R={ransomware_count}, P={portscan_count}, H={honeypot_hits}")
        return metric_id
    except Exception as e:
        logger.error(f"❌ Error storing metrics: {e}")
        return None


def get_metrics_for_session(session_id):
    """Get all metrics for a specific session."""
    try:
        results = execute_query(
            """SELECT timestamp, ransomware_count, portscan_count, honeypot_hits
               FROM scan_metrics
               WHERE session_id = ?
               ORDER BY timestamp ASC""",
            (session_id,)
        )
        return [dict(row) for row in results]
    except Exception as e:
        logger.error(f"❌ Error retrieving session metrics: {e}")
        return []


def get_latest_metrics(session_id):
    """Get the most recent metrics for a session."""
    try:
        results = execute_query(
            """SELECT timestamp, ransomware_count, portscan_count, honeypot_hits
               FROM scan_metrics
               WHERE session_id = ?
               ORDER BY timestamp DESC
               LIMIT 1""",
            (session_id,)
        )
        if results:
            return dict(results[0])
        return None
    except Exception as e:
        logger.error(f"❌ Error retrieving latest metrics: {e}")
        return None


def get_metrics_by_date(session_id, date_str):
    """
    Get metrics for a specific date.

    Args:
        session_id: ID of the scan session
        date_str: Date in format YYYY-MM-DD

    Returns:
        List of metrics matching the date
    """
    try:
        results = execute_query(
            """SELECT timestamp, ransomware_count, portscan_count, honeypot_hits
               FROM scan_metrics
               WHERE session_id = ? AND DATE(timestamp) = ?
               ORDER BY timestamp ASC""",
            (session_id, date_str)
        )
        return [dict(row) for row in results]
    except Exception as e:
        logger.error(f"❌ Error retrieving metrics by date: {e}")
        return []


def get_metrics_summary(session_id):
    """
    Get a summary of metrics for a session (max counts).

    Args:
        session_id: ID of the scan session

    Returns:
        Dictionary with max counts and statistics
    """
    try:
        results = execute_query(
            """SELECT
                MAX(ransomware_count) as max_ransomware,
                MAX(portscan_count) as max_portscan,
                MAX(honeypot_hits) as max_honeypot,
                COUNT(*) as total_readings,
                MIN(timestamp) as first_recorded,
                MAX(timestamp) as last_recorded
               FROM scan_metrics
               WHERE session_id = ?""",
            (session_id,)
        )
        if results:
            row = results[0]
            return {
                "max_ransomware": row['max_ransomware'] or 0,
                "max_portscan": row['max_portscan'] or 0,
                "max_honeypot": row['max_honeypot'] or 0,
                "total_readings": row['total_readings'] or 0,
                "first_recorded": row['first_recorded'],
                "last_recorded": row['last_recorded']
            }
        return None
    except Exception as e:
        logger.error(f"❌ Error retrieving metrics summary: {e}")
        return None
