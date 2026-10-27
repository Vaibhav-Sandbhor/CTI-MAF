"""Snapshot management for CyberSIEM session-based storage."""
import json
import logging
from datetime import datetime, timezone
from database.db_manager import execute_update, execute_query

logger = logging.getLogger(__name__)

MAX_TIMELINE_SNAPSHOTS = 5


def start_user_session(user_id: int) -> int:
    """Start a new scan session for a user and return the session ID."""
    try:
        # Always use UTC time in ISO format for consistency
        utc_start_time = datetime.now(timezone.utc).isoformat()
        session_id = execute_update(
            "INSERT INTO scan_sessions (user_id, status, start_time) VALUES (?, 'ACTIVE', ?)",
            (user_id, utc_start_time)
        )
        logger.info(f"✅ Started user session: {session_id} for user: {user_id} at {utc_start_time}")
        return session_id
    except Exception as e:
        logger.error(f"❌ Error starting user session: {e}")
        raise


def end_user_session(session_id: int, snapshot_data: dict) -> bool:
    """
    End a session and save the final snapshot.

    Args:
        session_id: The session to end
        snapshot_data: Complete dashboard state to store as JSON

    Returns:
        True if successful
    """
    try:
        # Save final snapshot
        save_session_snapshot(session_id, snapshot_data, snapshot_type='FINAL')

        # Update session status with UTC timestamp
        from datetime import timezone
        utc_time = datetime.now(timezone.utc).isoformat()
        execute_update(
            "UPDATE scan_sessions SET status = 'COMPLETED', end_time = ? WHERE id = ?",
            (utc_time, session_id)
        )
        logger.info(f"✅ Ended session {session_id} with final snapshot")
        return True
    except Exception as e:
        logger.error(f"❌ Error ending session {session_id}: {e}")
        raise


def save_session_snapshot(session_id: int, snapshot_data: dict, snapshot_type: str = 'FINAL') -> int:
    """
    Save a session snapshot (final state).

    Args:
        session_id: The session ID
        snapshot_data: Dashboard state dictionary
        snapshot_type: Type of snapshot ('FINAL' or 'MANUAL')

    Returns:
        Snapshot ID
    """
    try:
        utc_time = datetime.now(timezone.utc).isoformat()
        json_data = json.dumps(snapshot_data)
        snapshot_id = execute_update(
            "INSERT INTO session_snapshots (session_id, timestamp, snapshot_data, snapshot_type) VALUES (?, ?, ?, ?)",
            (session_id, utc_time, json_data, snapshot_type)
        )
        logger.info(f"✅ Saved {snapshot_type} snapshot {snapshot_id} for session {session_id}")
        return snapshot_id
    except Exception as e:
        logger.error(f"❌ Error saving snapshot: {e}")
        raise


def save_timeline_snapshot(session_id: int, snapshot_data: dict) -> int | None:
    """
    Save a timeline snapshot (limited to MAX_TIMELINE_SNAPSHOTS per session).

    Args:
        session_id: The session ID
        snapshot_data: Dashboard state dictionary

    Returns:
        Snapshot ID if saved, None if limit reached
    """
    try:
        # Check current count
        count_result = execute_query(
            "SELECT COUNT(*) as count FROM timeline_snapshots WHERE session_id = ?",
            (session_id,)
        )
        current_count = count_result[0]['count'] if count_result else 0

        if current_count >= MAX_TIMELINE_SNAPSHOTS:
            logger.info(f"⚠️ Timeline snapshot limit ({MAX_TIMELINE_SNAPSHOTS}) reached for session {session_id}")
            return None

        sequence_number = current_count + 1
        utc_time = datetime.now(timezone.utc).isoformat()
        json_data = json.dumps(snapshot_data)

        snapshot_id = execute_update(
            "INSERT INTO timeline_snapshots (session_id, timestamp, snapshot_data, sequence_number) VALUES (?, ?, ?, ?)",
            (session_id, utc_time, json_data, sequence_number)
        )
        logger.info(f"✅ Saved timeline snapshot {snapshot_id} (#{sequence_number}) for session {session_id}")
        return snapshot_id
    except Exception as e:
        logger.error(f"❌ Error saving timeline snapshot: {e}")
        raise


def get_timeline_snapshot_count(session_id: int) -> int:
    """Get the current number of timeline snapshots for a session."""
    try:
        result = execute_query(
            "SELECT COUNT(*) as count FROM timeline_snapshots WHERE session_id = ?",
            (session_id,)
        )
        return result[0]['count'] if result else 0
    except Exception as e:
        logger.error(f"❌ Error getting timeline count: {e}")
        return 0


def calculate_duration_seconds(start_time: str, end_time: str = None) -> int:
    """
    Calculate session duration in seconds.
    
    Args:
        start_time: ISO format start timestamp
        end_time: ISO format end timestamp (None for active sessions)
    
    Returns:
        Duration in seconds
    """
    try:
        # Parse start time
        start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        
        if end_time:
            # Completed session: use end time
            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        else:
            # Active session: calculate from current time
            end_dt = datetime.now(timezone.utc)
        
        duration = (end_dt - start_dt).total_seconds()
        return max(0, int(duration))
    except Exception as e:
        logger.error(f"Error calculating duration: {e}")
        return 0


def get_user_sessions(user_id: int, limit: int = 50) -> list:
    """
    Get all sessions for a user.
    
    Args:
        user_id: The user's ID
        limit: Maximum number of sessions to return
    
    Returns:
        List of session dictionaries with duration_seconds
    """
    try:
        # Order by datetime(start_time) DESC for proper chronological sorting
        results = execute_query(
            """SELECT id, user_id, start_time, end_time, status
               FROM scan_sessions
               WHERE user_id = ?
               ORDER BY datetime(start_time) DESC
               LIMIT ?""",
            (user_id, limit)
        )
        
        sessions = []
        for row in results:
            session = dict(row)
            # Calculate duration for each session
            session['duration_seconds'] = calculate_duration_seconds(
                session.get('start_time'),
                session.get('end_time')
            )
            sessions.append(session)
        
        logger.info(f"📋 Found {len(sessions)} sessions for user {user_id}")
        return sessions
    except Exception as e:
        logger.error(f"❌ Error fetching user sessions: {e}")
        return []


def get_session_detail(session_id: int, user_id: int = None) -> dict | None:
    """
    Get session details including all snapshots.
    
    Args:
        session_id: The session ID
        user_id: Optional user ID for security validation
    
    Returns:
        Session data with snapshots and duration_seconds, or None if not found
    """
    try:
        # Get session info
        session_query = "SELECT id, user_id, start_time, end_time, status FROM scan_sessions WHERE id = ?"
        params = [session_id]
        
        if user_id is not None:
            session_query += " AND user_id = ?"
            params.append(user_id)
        
        session_result = execute_query(session_query, tuple(params))
        
        if not session_result:
            logger.warning(f"⚠️ Session {session_id} not found")
            return None
        
        session = dict(session_result[0])
        
        # Add duration calculation
        session['duration_seconds'] = calculate_duration_seconds(
            session.get('start_time'),
            session.get('end_time')
        )
        
        # Get final snapshot
        final_snapshot = execute_query(
            """SELECT id, timestamp, snapshot_data, snapshot_type
               FROM session_snapshots
               WHERE session_id = ?
               ORDER BY timestamp DESC
               LIMIT 1""",
            (session_id,)
        )
        
        if final_snapshot:
            snapshot = dict(final_snapshot[0])
            snapshot['snapshot_data'] = json.loads(snapshot['snapshot_data'])
            session['final_snapshot'] = snapshot
        else:
            session['final_snapshot'] = None
        
        # Get timeline snapshots
        timeline_results = execute_query(
            """SELECT id, timestamp, snapshot_data, sequence_number
               FROM timeline_snapshots
               WHERE session_id = ?
               ORDER BY sequence_number ASC""",
            (session_id,)
        )
        
        timeline = []
        for row in timeline_results:
            snapshot = dict(row)
            snapshot['snapshot_data'] = json.loads(snapshot['snapshot_data'])
            timeline.append(snapshot)
        
        session['timeline_snapshots'] = timeline
        
        logger.info(f"📋 Retrieved session {session_id} with {len(timeline)} timeline snapshots")
        return session
    except Exception as e:
        logger.error(f"❌ Error fetching session detail: {e}")
        return None


def get_active_session_for_user(user_id: int) -> int | None:
    """Get the active session ID for a user, if any."""
    try:
        result = execute_query(
            "SELECT id FROM scan_sessions WHERE user_id = ? AND status = 'ACTIVE' ORDER BY start_time DESC LIMIT 1",
            (user_id,)
        )
        if result:
            return result[0]['id']
        return None
    except Exception as e:
        logger.error(f"❌ Error getting active session: {e}")
        return None
