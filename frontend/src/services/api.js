const API_BASE = import.meta.env.VITE_MAIN_API_BASE || "http://127.0.0.1:8000";

// Helper function to get JWT token from localStorage
function getAuthHeaders() {
  const token = localStorage.getItem("auth-token");
  const headers = { "Content-Type": "application/json" };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

// ---------------------------------------------------------------------------
// Authentication API
// ---------------------------------------------------------------------------

export const registerUser = async (name, email, password) => {
  const response = await fetch(`${API_BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, email, password }),
  });
  return response.json();
};

export const loginUser = async (email, password) => {
  const response = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  return response.json();
};

export const getCurrentUser = async () => {
  try {
    const response = await fetch(`${API_BASE}/auth/me`, {
      method: "GET",
      headers: getAuthHeaders(),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || "Failed to get user");
    }
    return response.json();
  } catch (err) {
    console.error("getCurrentUser error:", err);
    throw err;
  }
};

/**
 * Update user profile (name and/or role).
 * @param {Object} profileData - { name?: string, role?: string }
 */
export const updateProfile = async (profileData) => {
  const response = await fetch(`${API_BASE}/auth/profile`, {
    method: "PUT",
    headers: getAuthHeaders(),
    body: JSON.stringify(profileData),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || "Failed to update profile");
  }
  return response.json();
};

/**
 * Change user password.
 * @param {string} currentPassword - Current password
 * @param {string} newPassword - New password (min 6 chars)
 */
export const changePassword = async (currentPassword, newPassword) => {
  const response = await fetch(`${API_BASE}/auth/password`, {
    method: "PUT",
    headers: getAuthHeaders(),
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
    }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || "Failed to change password");
  }
  return response.json();
};

export const fetchAlerts = async () => {
  const response = await fetch(`${API_BASE}/api/alerts`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const fetchDashboardStats = async () => {
  const response = await fetch(`${API_BASE}/api/dashboard`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const scanRansomware = async (samplePath) => {
  const response = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sample_path: samplePath, label: 1 }),
  });
  return response.json();
};

// ---------------------------------------------------------------------------
// Ransomware Module Pipeline API
// ---------------------------------------------------------------------------

export const runRansomwarePipeline = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/run-pipeline`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const fetchRansomwarePredictions = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/predictions`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const fetchRansomwareAlerts = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/alerts`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const scanRealSystem = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/scan-real-system`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const startSimulationScan = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/start-scan-simulation`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const startSystemScan = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/start-scan-system`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const stopScan = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/stop-scan`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const getScanStatus = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/scan-status`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

// ---------------------------------------------------------------------------
// Honeypot Module API
// ---------------------------------------------------------------------------

export const fetchHoneypotLog = async () => {
  const response = await fetch(`${API_BASE}/api/honeypot/log`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const startHoneypotSimulation = async () => {
  const response = await fetch(`${API_BASE}/api/honeypot/start-simulation`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const startHoneypotMonitor = async () => {
  const response = await fetch(`${API_BASE}/api/honeypot/start-monitor`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const stopHoneypotScan = async () => {
  const response = await fetch(`${API_BASE}/api/honeypot/stop`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const getHoneypotScanStatus = async () => {
  const response = await fetch(`${API_BASE}/api/honeypot/scan-status`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

// ---------------------------------------------------------------------------
// Port Scan API (via main backend - no separate service needed)
// ---------------------------------------------------------------------------

/**
 * Check Nmap installation status (no auth required)
 */
export const checkNmapStatus = async () => {
  const response = await fetch(`${API_BASE}/api/portscan/status`);
  if (!response.ok) throw new Error(`Status check failed: ${response.status}`);
  return response.json();
};

/**
 * Scan localhost ports using the main API backend.
 * This uses the integrated Nmap scanner in api_server.py
 */
export const scanSystemPorts = async () => {
  const response = await fetch(`${API_BASE}/api/portscan/scan`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error(`Port scan failed: ${response.status}`);
  return response.json();
};

/**
 * Start a port scan on a specific target.
 * Falls back to localhost scan via main API.
 */
export const startPortScan = async (target = "127.0.0.1") => {
  // Use the main backend's port scan endpoint
  const response = await fetch(`${API_BASE}/api/portscan/scan`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error(`Port scan failed: ${response.status}`);
  return response.json();
};

/**
 * Fetch port scan report (placeholder - data comes from scanSystemPorts)
 */
export const fetchPortScanReport = async (scanId) => {
  // Port scan results are returned directly from scanSystemPorts
  // This is a no-op placeholder for compatibility
  return { status: "use scanSystemPorts instead" };
};

// ---------------------------------------------------------------------------
// Security Metrics API - Real-time threat aggregation
// ---------------------------------------------------------------------------

export const getSecurityMetrics = async () => {
  const response = await fetch(`${API_BASE}/api/security-metrics`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error(`Failed to fetch security metrics: ${response.status}`);
  return response.json();
};

// ---------------------------------------------------------------------------
// Historical Data Viewer API
// ---------------------------------------------------------------------------

export const getHistoryDates = async () => {
  const response = await fetch(`${API_BASE}/history/dates`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error("Failed to fetch history dates");
  return response.json();
};

export const getHistoryMetrics = async (date) => {
  const response = await fetch(`${API_BASE}/history/metrics?date=${date}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error(`Failed to fetch metrics for ${date}`);
  return response.json();
};

export const getHistoryEvents = async (date) => {
  const response = await fetch(`${API_BASE}/history/events?date=${date}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error(`Failed to fetch events for ${date}`);
  return response.json();
};

export const getHistoryHealth = async () => {
  const response = await fetch(`${API_BASE}/health/history`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

// ---------------------------------------------------------------------------
// Session-Based Storage API (Optimized - stores only at logout + optional timeline)
// ---------------------------------------------------------------------------

/**
 * Start a new session for the authenticated user.
 * Call this after successful login.
 */
export const startUserSession = async () => {
  const response = await fetch(`${API_BASE}/api/session/start`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error("Failed to start session");
  return response.json();
};

/**
 * End the user's session and save the final dashboard snapshot.
 * Call this before logout.
 * @param {Object} snapshotData - Complete dashboard state
 * @param {Object} snapshotData.summary - Summary metrics (total_events, ransomware_critical, etc.)
 * @param {Object} snapshotData.ransomware - Ransomware details (total_processes, ransomware, etc.)
 * @param {Array} snapshotData.ports - Port scan results array
 */
export const endUserSession = async (snapshotData) => {
  const response = await fetch(`${API_BASE}/api/session/end`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: JSON.stringify(snapshotData),
  });
  if (!response.ok) throw new Error("Failed to end session");
  return response.json();
};

/**
 * Save an optional timeline snapshot (max 5 per session).
 * Call this periodically during session - NOT every scan cycle.
 * @param {Object} snapshotData - Dashboard state to save
 */
export const saveTimelineSnapshot = async (snapshotData) => {
  const response = await fetch(`${API_BASE}/api/session/snapshot`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: JSON.stringify(snapshotData),
  });
  if (!response.ok) throw new Error("Failed to save timeline snapshot");
  return response.json();
};

/**
 * Get list of all sessions for the authenticated user.
 * Returns sessions ordered by start time (newest first).
 */
export const getUserSessions = async () => {
  const response = await fetch(`${API_BASE}/history/sessions`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error("Failed to fetch user sessions");
  return response.json();
};

/**
 * Get detailed session data including final snapshot and timeline.
 * Use this to replay a historical session on the dashboard.
 * @param {number} sessionId - The session ID to retrieve
 */
export const getSessionDetail = async (sessionId) => {
  const response = await fetch(`${API_BASE}/history/session/${sessionId}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error("Failed to fetch session detail");
  return response.json();
};

