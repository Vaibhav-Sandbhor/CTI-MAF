# CyberSIEM Database Integration

SQLite-based persistence layer for scan sessions, threat events, and security metrics.

## 📊 Database Schema

### 1. **scan_sessions**
Tracks individual scan sessions.

```sql
CREATE TABLE scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    status TEXT DEFAULT 'ACTIVE',  -- 'ACTIVE' or 'COMPLETED'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

### 2. **threat_events**
Records all detected threats from each module.

```sql
CREATE TABLE threat_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    module TEXT NOT NULL,              -- 'ransomware', 'portscan', 'honeypot'
    event_type TEXT NOT NULL,          -- e.g., 'encryption_activity', 'port_detected'
    severity TEXT NOT NULL,            -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    details TEXT,                      -- Additional context about the threat
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
)

-- Indexes for faster queries
CREATE INDEX idx_threat_events_session ON threat_events(session_id)
CREATE INDEX idx_threat_events_timestamp ON threat_events(timestamp)
```

### 3. **scan_metrics**
Stores threat counts after each scan cycle.

```sql
CREATE TABLE scan_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    ransomware_count INTEGER DEFAULT 0,
    portscan_count INTEGER DEFAULT 0,
    honeypot_hits INTEGER DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
)

-- Indexes for faster queries
CREATE INDEX idx_scan_metrics_session ON scan_metrics(session_id)
CREATE INDEX idx_scan_metrics_timestamp ON scan_metrics(timestamp)
```

## 🔧 Core Modules

### `db_manager.py`
Low-level database connection management.

```python
from database.db_manager import get_db, execute_query, execute_update

# Get data
results = execute_query("SELECT * FROM threat_events WHERE session_id = ?", (1,))

# Insert/Update data
event_id = execute_update("INSERT INTO threat_events (...) VALUES (...)", params)
```

### `init_db.py`
Initializes database tables on server startup.

```python
from database.init_db import init_database

init_database()  # Creates all tables and indexes
```

### `session_manager.py`
Manages scan session lifecycle.

```python
from database.session_manager import start_session, end_session

session_id = start_session()          # Begin a new session
end_session(session_id)               # Mark session as COMPLETED
```

### `event_logger.py`
Logs threat events to the database.

```python
from database.event_logger import log_ransomware_threat, log_port_open, log_honeypot_interaction

# Log ransomware detection
log_ransomware_threat(session_id, threat_count=5, details="Detected via LSTM")

# Log open port
log_port_open(session_id, port=22, risk_level="HIGH", details="SSH service")

# Log honeypot interaction
log_honeypot_interaction(session_id, interaction_count=3, details="Decoy files accessed")
```

### `metrics_manager.py`
Stores and retrieves security metrics.

```python
from database.metrics_manager import store_metrics, get_metrics_for_session

# Store metrics after scan
store_metrics(session_id, ransomware_count=5, portscan_count=2, honeypot_hits=1)

# Retrieve metrics for timeline
metrics = get_metrics_for_session(session_id)
```

## 🚀 API Endpoints

### Data Retrieval Endpoints (NEW)

#### `GET /api/metrics`
Get metrics timeline for a session.

**Response:**
```json
{
  "metrics": [
    {
      "timestamp": "2026-04-06 10:30:45",
      "ransomware_count": 5,
      "portscan_count": 2,
      "honeypot_hits": 1
    }
  ],
  "session_id": 1
}
```

#### `GET /api/events`
Get all threat events from current session (latest 100).

**Response:**
```json
{
  "events": [
    {
      "module": "ransomware",
      "event_type": "encryption_activity",
      "severity": "CRITICAL",
      "details": "Detected 5 ransomware threat(s)",
      "timestamp": "2026-04-06 10:30:45"
    }
  ],
  "total": 15
}
```

#### `GET /api/events/by-date?date=2026-04-06`
Get threat events for a specific date.

**Query Parameters:**
- `date`: Date in format `YYYY-MM-DD`

**Response:**
```json
{
  "date": "2026-04-06",
  "events": [...],
  "total": 8
}
```

#### `GET /api/metrics/summary`
Get summary statistics for metrics.

**Response:**
```json
{
  "max_ransomware": 10,
  "max_portscan": 5,
  "max_honeypot": 3,
  "total_readings": 45,
  "first_recorded": "2026-04-06 09:00:00",
  "last_recorded": "2026-04-06 15:45:00"
}
```

## 🔗 Integration Points in api_server.py

### 1. **Initialization** (Startup)
```python
@app.on_event("startup")
async def startup_event():
    global CURRENT_SESSION_ID

    if ENABLE_DB:
        init_database()
        CURRENT_SESSION_ID = start_session()
```

### 2. **Ransomware Pipeline** (Line ~570)
```python
# After predictions and summary generation
if summary["ransomware"] > 0:
    log_ransomware_threat(CURRENT_SESSION_ID, summary["ransomware"], details)
```

### 3. **Port Scan** (Line ~1331)
```python
# For each open port
for port in ports:
    log_port_open(CURRENT_SESSION_ID, port["port"], port["risk"], details)
```

### 4. **Honeypot** (Line ~1250)
```python
# After generating honeypot summary
if summary["critical"] > 0:
    log_honeypot_interaction(CURRENT_SESSION_ID, summary["critical"], details)
```

## 📈 Frontend Integration

The frontend can now fetch historical data and metrics:

```javascript
// Get metrics timeline for charts
const metrics = await fetch('/api/metrics').then(r => r.json());

// Get threat events
const events = await fetch('/api/events').then(r => r.json());

// Get historical data for a date
const dateEvents = await fetch('/api/events/by-date?date=2026-04-06')
  .then(r => r.json());
```

## 🗄️ Database File

**Location:** `./cybersiem_data.db`

SQLite database file is created automatically on first startup.

**Size consideration:** Metrics stored every 30 seconds + events logged per detection. A typical day of scanning generates ~2KB of data.

## ⚠️ Important Notes

1. **Non-Breaking**: All existing API responses remain unchanged
2. **Optional**: If database module import fails, server continues without persistence
3. **Session-based**: Each server restart creates a new session
4. **Retention**: Data persists across server restarts (stored in SQLite)
5. **Performance**: Indexed queries ensure minimal overhead

## 🧪 Testing

Reset/delete the database to start fresh:

```bash
rm cybersiem_data.db
# Server will recreate it on next startup
```

## 📝 Example Workflow

1. **Server starts** → Database initialized, Session 1 created
2. **Ransomware scan runs** → Predictions generated, events logged to DB
3. **Port scan runs** → Open ports logged as events
4. **Honeypot monitor runs** → Interactions logged as events
5. **Metrics stored** → Threat counts recorded per scan cycle
6. **Frontend fetches** → `/api/metrics` and `/api/events` return historical data
7. **Charts update** → LineChart renders metrics timeline
8. **User can query** → `/api/events/by-date` retrieves specific date events

## 🔐 Security

- Database access requires JWT authentication (same as other endpoints)
- No sensitive user data stored in metrics/events table
- Error messages are generic to prevent information leakage
