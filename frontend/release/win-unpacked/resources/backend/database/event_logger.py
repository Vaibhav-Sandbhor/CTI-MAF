"""Event logging for threat detection in CyberSIEM."""
import logging
from database.db_manager import execute_update

logger = logging.getLogger(__name__)


def log_event(session_id, module, event_type, severity, details=None):
    """
    Log a threat event to the database.

    Args:
        session_id: ID of the scan session
        module: Module name (ransomware, portscan, honeypot)
        event_type: Type of event (e.g., encryption_activity, port_detected, file_access)
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        details: Additional details about the event
    """
    try:
        event_id = execute_update(
            """INSERT INTO threat_events
               (session_id, module, event_type, severity, details)
               VALUES (?, ?, ?, ?, ?)""",
            (session_id, module, event_type, severity, details)
        )
        logger.info(f"📝 Logged event {event_id}: {module}/{event_type} ({severity})")
        return event_id
    except Exception as e:
        logger.error(f"❌ Error logging event: {e}")
        return None


def log_ransomware_threat(session_id, threat_count, details=None):
    """Log a ransomware threat detection."""
    return log_event(
        session_id,
        "ransomware",
        "encryption_activity",
        "CRITICAL" if threat_count > 0 else "LOW",
        details or f"Detected {threat_count} ransomware threat(s)"
    )


def log_port_open(session_id, port, risk_level, details=None):
    """Log an open port detection."""
    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW"
    }
    severity = severity_map.get(risk_level, "MEDIUM")

    return log_event(
        session_id,
        "portscan",
        "port_detected",
        severity,
        details or f"Port {port} is open (Risk: {risk_level})"
    )


def log_honeypot_interaction(session_id, interaction_count, details=None):
    """Log honeypot file interactions."""
    return log_event(
        session_id,
        "honeypot",
        "file_access",
        "HIGH" if interaction_count > 0 else "LOW",
        details or f"Detected {interaction_count} honeypot interaction(s)"
    )
