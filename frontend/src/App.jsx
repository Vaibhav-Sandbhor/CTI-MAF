import React, { useState, useEffect, useCallback, useRef } from "react";
import { Routes, Route, Navigate } from "react-router-dom";

import { AuthProvider, useAuth } from "./context/AuthContext.jsx";
import { ProtectedRoute } from "./components/ProtectedRoute.jsx";
import Sidebar from "./components/Sidebar.jsx";
import AlertsPanel from "./components/AlertsPanel.jsx";
import Topbar from "./components/Topbar.jsx";

import Dashboard from "./pages/Dashboard.jsx";
import Login from "./pages/Login.jsx";
import Register from "./pages/Register.jsx";
import LandingPage from "./pages/LandingPage.jsx";
import HistoryViewer from "./pages/HistoryViewer.jsx";
import SessionHistory from "./pages/SessionHistory.jsx";
import Profile from "./pages/Profile.jsx";
import PortScanDetails from "./pages/details/PortScanDetails.jsx";
import HoneypotDetails from "./pages/details/HoneypotDetails.jsx";
import DarkWebDetails from "./pages/details/DarkWebDetails.jsx";
import RansomwareDetails from "./pages/details/RansomwareDetails.jsx";
import {
  runRansomwarePipeline,
  fetchRansomwarePredictions,
  scanSystemPorts,
  fetchHoneypotLog,
  saveTimelineSnapshot,
} from "./services/api.js";

function AppContent() {
  const { isAuthenticated, loading, registerDashboardStateGetter, registerDashboardStateResetter, sessionId } = useAuth();

  // ✅ Set document title to ensure consistent branding
  useEffect(() => {
    document.title = "SentraX";
  }, []);

  // Initial empty state for dashboard
  const initialModuleData = {
    ransomware: {
      count: null,
      status: "IDLE",
      summary: null,
      predictions: [],
      alerts: [],
      lastScan: null,
    },
    portscan: {
      count: null,
      status: "IDLE",
      scanData: null,
      lastScan: null,
    },
    honeypot: {
      count: null,
      status: "IDLE",
      summary: null,
      events: [],
      alerts: [],
      lastScan: null,
    },
  };
  
  const [moduleData, setModuleData] = useState(initialModuleData);
  const [alerts, setAlerts] = useState([]);
  
  // Track if any scan has been run this session
  const [hasScanRun, setHasScanRun] = useState(false);

  // ✅ SEPARATE STATE FOR LIVE AND HISTORY TIMELINE DATA
  // Live timeline data - NEVER modified when viewing history
  const [liveTimelineData, setLiveTimelineData] = useState([]);
  // History timeline data - only set when viewing a historical session
  const [historyTimelineData, setHistoryTimelineData] = useState([]);

  // State for auto-scanning system
  const [previousCounts, setPreviousCounts] = useState({
    ransomware: 0,
    portscan: 0,
    honeypot: 0,
  });
  const [autoScanInterval, setAutoScanInterval] = useState(null);
  const [scanMode, setScanMode] = useState("simulation");

  // ✅ SESSION-BASED STORAGE: Track scan count for timeline snapshots
  const [scanCount, setScanCount] = useState(0);
  const [timelineSnapshotCount, setTimelineSnapshotCount] = useState(0);
  const MAX_TIMELINE_SNAPSHOTS = 5;

  // ✅ HISTORY MODE: Switch between live and history viewing
  const [viewMode, setViewMode] = useState("live"); // "live" | "history"
  const [historySnapshot, setHistorySnapshot] = useState(null);

  // ✅ DERIVED STATE: Current timeline data based on mode
  const currentTimelineData = viewMode === "live" ? liveTimelineData : historyTimelineData;
  
  // Safe setter that only updates live data (ignores updates when in history mode)
  const setTimelineDataSafe = useCallback((updater) => {
    // Only update live timeline data, never history
    setLiveTimelineData(updater);
  }, []);

  // Ref to always have the latest version of runAllScansParallel
  const runAllScansParallelRef = useRef(null);
  
  // Ref to latest moduleData for snapshot creation
  const moduleDataRef = useRef(moduleData);
  useEffect(() => {
    moduleDataRef.current = moduleData;
  }, [moduleData]);

  // Register dashboard state getter with AuthContext for logout snapshot
  useEffect(() => {
    if (registerDashboardStateGetter) {
      registerDashboardStateGetter(() => {
        const data = moduleDataRef.current;
        return {
          summary: {
            total_events: (data.ransomware?.summary?.total || 0) + 
                         (data.portscan?.scanData?.dashboard?.[0]?.total_ports || 0) + 
                         (data.honeypot?.summary?.total || 0),
            ransomware_critical: data.ransomware?.summary?.ransomware || 0,
            warning: data.ransomware?.summary?.suspicious || 0,
            benign: data.ransomware?.summary?.benign || 0,
            ml_alerts: 0,
          },
          ransomware: {
            total_processes: data.ransomware?.summary?.total || 0,
            ransomware: data.ransomware?.summary?.ransomware || 0,
            suspicious: data.ransomware?.summary?.suspicious || 0,
            benign: data.ransomware?.summary?.benign || 0,
          },
          ports: data.portscan?.scanData?.ports || [],
        };
      });
    }
  }, [registerDashboardStateGetter]);

  // Register dashboard state resetter with AuthContext for logout/login cleanup
  const resetDashboardState = useCallback(() => {
    setModuleData(initialModuleData);
    setAlerts([]);
    setLiveTimelineData([]);
    setHistoryTimelineData([]);
    setPreviousCounts({ ransomware: 0, portscan: 0, honeypot: 0 });
    setScanCount(0);
    setTimelineSnapshotCount(0);
    setHasScanRun(false);
    setViewMode("live");
    setHistorySnapshot(null);
    console.log("🔄 Dashboard state reset to initial values");
  }, []);

  useEffect(() => {
    if (registerDashboardStateResetter) {
      registerDashboardStateResetter(resetDashboardState);
    }
  }, [registerDashboardStateResetter, resetDashboardState]);

  // Load previousCounts from localStorage on mount (only if scan has run)
  useEffect(() => {
    const stored = localStorage.getItem("soc-dashboard-previousCounts");
    if (stored) {
      try {
        setPreviousCounts(JSON.parse(stored));
      } catch (e) {
        console.error("Failed to load previousCounts from localStorage:", e);
      }
    }
  }, []);

  // Update ref to always have the latest version of runAllScansParallel
  // This is inserted after runAllScansParallel is defined below

  // Cleanup auto-scan interval on unmount
  useEffect(() => {
    return () => {
      if (autoScanInterval) {
        clearInterval(autoScanInterval);
      }
    };
  }, [autoScanInterval]);

  const updateModuleData = (key, patch) => {
    setModuleData((prev) => ({
      ...prev,
      [key]: {
        ...prev[key],
        ...patch,
      },
    }));
  };

  // Generate alerts based on count deltas (new threats only)
  const generateNewAlerts = (oldCounts, newCounts) => {
    console.log("[generateNewAlerts] Old:", oldCounts, "New:", newCounts);
    const newAlerts = [];

    // Ransomware alerts
    const ransomwareDelta = newCounts.ransomware - oldCounts.ransomware;
    if (ransomwareDelta > 0) {
      newAlerts.push({
        severity: "critical",
        message: `[RANSOMWARE] New threat detected: ${ransomwareDelta} additional instance${ransomwareDelta > 1 ? "s" : ""} (+${ransomwareDelta})`,
        time: new Date().toLocaleTimeString(),
        module: "ransomware",
      });
    }

    // Port Scan alerts
    const portscanDelta = newCounts.portscan - oldCounts.portscan;
    if (portscanDelta > 0) {
      newAlerts.push({
        severity: "high",
        message: `[PORT SCAN] High-risk ports exposed: ${portscanDelta} additional port${portscanDelta > 1 ? "s" : ""} (+${portscanDelta})`,
        time: new Date().toLocaleTimeString(),
        module: "portscan",
      });
    }

    // Honeypot alerts
    const honeypotDelta = newCounts.honeypot - oldCounts.honeypot;
    if (honeypotDelta > 0) {
      newAlerts.push({
        severity: "medium",
        message: `[HONEYPOT] Critical file interactions: ${honeypotDelta} additional event${honeypotDelta > 1 ? "s" : ""} (+${honeypotDelta})`,
        time: new Date().toLocaleTimeString(),
        module: "honeypot",
      });
    }

    // Push new alerts to the front of alerts list
    if (newAlerts.length > 0) {
      console.log("[generateNewAlerts] Pushing alerts:", newAlerts);
      setAlerts((prev) => [...newAlerts, ...prev]);
    } else {
      console.log("[generateNewAlerts] No deltas detected");
    }
  };

  // ✅ Save timeline snapshot (called every 3rd scan, max 5 per session)
  const maybeSaveTimelineSnapshot = useCallback(async (currentModuleData) => {
    if (timelineSnapshotCount >= MAX_TIMELINE_SNAPSHOTS) {
      return; // Already at max
    }

    const snapshotData = {
      summary: {
        total_events: (currentModuleData.ransomware?.summary?.total || 0) + 
                     (currentModuleData.portscan?.scanData?.dashboard?.[0]?.total_ports || 0) + 
                     (currentModuleData.honeypot?.summary?.total || 0),
        ransomware_critical: currentModuleData.ransomware?.summary?.ransomware || 0,
        warning: currentModuleData.ransomware?.summary?.suspicious || 0,
        benign: currentModuleData.ransomware?.summary?.benign || 0,
        ml_alerts: 0,
      },
      ransomware: {
        total_processes: currentModuleData.ransomware?.summary?.total || 0,
        ransomware: currentModuleData.ransomware?.summary?.ransomware || 0,
        suspicious: currentModuleData.ransomware?.summary?.suspicious || 0,
        benign: currentModuleData.ransomware?.summary?.benign || 0,
      },
      ports: currentModuleData.portscan?.scanData?.ports || [],
    };

    try {
      const result = await saveTimelineSnapshot(snapshotData);
      if (result.status === "saved") {
        setTimelineSnapshotCount(result.count);
        console.log(`📸 Timeline snapshot saved (${result.count}/${MAX_TIMELINE_SNAPSHOTS})`);
      }
    } catch (error) {
      console.error("Failed to save timeline snapshot:", error);
    }
  }, [timelineSnapshotCount]);

  // Run all three scans in parallel
  const runAllScansParallel = useCallback(async () => {
    // Don't run scans in history mode
    if (viewMode === "history") {
      console.log("[runAllScansParallel] Skipping - in history mode");
      return null;
    }

    console.log("[runAllScansParallel] Starting scans...");
    try {
      const [ransomwareRes, portscanRes, honeypotRes] = await Promise.all([
        runRansomwarePipeline().catch((e) => ({
          status: "error",
          error: e.message,
        })),
        scanSystemPorts().catch((e) => ({
          status: "error",
          error: e.message,
        })),
        fetchHoneypotLog().catch((e) => ({
          status: "error",
          error: e.message,
        })),
      ]);

      // Extract new counts
      const newCounts = {
        ransomware: ransomwareRes?.summary?.ransomware ?? moduleData.ransomware.count ?? 0,
        portscan: portscanRes?.dashboard?.[0]?.total_ports ?? moduleData.portscan.count ?? 0,
        honeypot: honeypotRes?.summary?.total ?? moduleData.honeypot.count ?? 0,
      };

      console.log("[runAllScansParallel] New counts:", newCounts);
      console.log("[runAllScansParallel] Current previousCounts:", previousCounts);

      // Generate alerts based on deltas
      generateNewAlerts(previousCounts, newCounts);

      // Update previousCounts state and localStorage
      setPreviousCounts(newCounts);
      localStorage.setItem("soc-dashboard-previousCounts", JSON.stringify(newCounts));

      // Update module data
      const newModuleData = { ...moduleData };

      // Ransomware
      newModuleData.ransomware = {
        ...moduleData.ransomware,
        count: newCounts.ransomware,
        status: ransomwareRes?.summary?.ransomware > 0 ? "MALICIOUS" : "SAFE",
        summary: ransomwareRes?.summary || null,
        lastScan: new Date().toISOString(),
      };
      updateModuleData("ransomware", newModuleData.ransomware);

      // Port Scan
      newModuleData.portscan = {
        ...moduleData.portscan,
        count: newCounts.portscan,
        status:
          portscanRes?.dashboard?.[0]?.final_risk &&
          ["CRITICAL", "HIGH"].includes(portscanRes.dashboard[0].final_risk)
            ? "MALICIOUS"
            : "SAFE",
        scanData: portscanRes || null,
        lastScan: new Date().toISOString(),
      };
      updateModuleData("portscan", newModuleData.portscan);

      // Honeypot
      newModuleData.honeypot = {
        ...moduleData.honeypot,
        count: newCounts.honeypot,
        status: honeypotRes?.summary?.critical > 0 ? "MALICIOUS" : "SAFE",
        summary: honeypotRes?.summary || null,
        events: honeypotRes?.events || [],
        lastScan: new Date().toISOString(),
      };
      updateModuleData("honeypot", newModuleData.honeypot);

      // ✅ SESSION-BASED STORAGE: Save timeline snapshot every 3rd scan
      const newScanCount = scanCount + 1;
      setScanCount(newScanCount);
      if (newScanCount % 3 === 0 && sessionId) {
        maybeSaveTimelineSnapshot(newModuleData);
      }

      // Mark that a scan has been run this session
      setHasScanRun(true);

      return newCounts;
    } catch (error) {
      console.error("Error running all scans:", error);
      return null;
    }
  }, [moduleData, previousCounts, viewMode, scanCount, sessionId, maybeSaveTimelineSnapshot]);

  // Update ref with latest version of runAllScansParallel
  // This ensures the interval always calls the latest version
  useEffect(() => {
    runAllScansParallelRef.current = runAllScansParallel;
  }, [runAllScansParallel]);

  // Start auto-scan 30 seconds after first global scan
  const startAutoScan = useCallback(() => {
    console.log("[startAutoScan] Called, autoScanInterval status:", autoScanInterval);
    if (autoScanInterval) {
      console.log("[startAutoScan] Auto-scan already running, skipping");
      return; // Already running
    }

    // Set initial delay of 30 seconds
    const timeout = setTimeout(() => {
      console.log("[startAutoScan] Initial 30s timeout completed, creating interval");
      // Create a repeating interval that calls the latest version via ref
      const interval = setInterval(() => {
        console.log("[startAutoScan] Interval triggered, calling runAllScansParallel via ref");
        if (runAllScansParallelRef.current) {
          runAllScansParallelRef.current();
        } else {
          console.warn("[startAutoScan] runAllScansParallelRef.current is null!");
        }
      }, 30000); // 30 seconds

      setAutoScanInterval(interval);
      console.log("[startAutoScan] Interval created:", interval);
    }, 30000);

    // Store timeout ID for cleanup if needed
    return () => clearTimeout(timeout);
  }, [autoScanInterval]);

  // ✅ Stop auto-scan (used when switching to history mode)
  const stopAutoScan = useCallback(() => {
    if (autoScanInterval) {
      clearInterval(autoScanInterval);
      setAutoScanInterval(null);
      console.log("[stopAutoScan] Auto-scan stopped");
    }
  }, [autoScanInterval]);

  // ✅ Switch to history mode with a snapshot
  const switchToHistoryMode = useCallback((snapshot, timelinePoints = []) => {
    stopAutoScan();
    setViewMode("history");
    setHistorySnapshot(snapshot);
    // Set history timeline data (if available from the snapshot)
    setHistoryTimelineData(timelinePoints);
    console.log("[switchToHistoryMode] Switched to history mode, live data preserved");
    console.log("[switchToHistoryMode] Snapshot portscan count:", snapshot?.portscan?.count);
    console.log("[switchToHistoryMode] Full snapshot:", snapshot);
  }, [stopAutoScan]);

  // ✅ Switch back to live mode - NEVER resets live data
  const switchToLiveMode = useCallback(() => {
    setViewMode("live");
    setHistorySnapshot(null);
    setHistoryTimelineData([]); // Clear history timeline, but live data is untouched
    console.log("[switchToLiveMode] Switched to live mode, live data restored");
  }, []);

  // Expose functions to Dashboard via props
  const scanFunctions = { 
    runAllScansParallel, 
    startAutoScan, 
    stopAutoScan,
    switchToHistoryMode,
    switchToLiveMode,
  };

  return (
    <>
      {loading ? (
        <div style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          height: "100vh",
          fontSize: "18px",
          color: "#888",
          background: "linear-gradient(135deg, #0f0f1e 0%, #1a1a2e 100%)",
        }}>
          Loading...
        </div>
      ) : !isAuthenticated ? (
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      ) : (
        <>
          <Routes>
            {/* History Viewer - Full Page (Date-based) */}
            <Route
              path="/history"
              element={
                <ProtectedRoute>
                  <HistoryViewer />
                </ProtectedRoute>
              }
            />

            {/* Session History - Full Page (Session-based) */}
            <Route
              path="/sessions"
              element={
                <ProtectedRoute>
                  <SessionHistory 
                    onSelectSession={switchToHistoryMode}
                    onBackToLive={switchToLiveMode}
                  />
                </ProtectedRoute>
              }
            />

            {/* Profile Page */}
            <Route
              path="/profile"
              element={
                <ProtectedRoute>
                  <Profile />
                </ProtectedRoute>
              }
            />

            {/* All Dashboard Routes */}
            <Route
              path="*"
              element={
                <div className="app-wrapper">
                  {/* ✅ GLOBAL TOPBAR */}
                  <Topbar viewMode={viewMode} onSwitchToLive={switchToLiveMode} />

                  {/* ✅ MAIN DASHBOARD GRID */}
                  <div className="dashboard-layout">
                    <Sidebar />

                    <main className="dashboard-main">
                      <Routes>
                        {/* Main Dashboard - accessible at / or /dashboard */}
                        <Route
                          path="/"
                          element={
                            <ProtectedRoute>
                              <Dashboard
                                moduleData={viewMode === "history" && historySnapshot ? historySnapshot : moduleData}
                                updateModuleData={updateModuleData}
                                alerts={alerts}
                                setAlerts={setAlerts}
                                scanFunctions={scanFunctions}
                                timelineData={currentTimelineData}
                                setTimelineData={setTimelineDataSafe}
                                viewMode={viewMode}
                                hasScanRun={hasScanRun}
                              />
                            </ProtectedRoute>
                          }
                        />
                        {/* Redirect /dashboard to / for compatibility */}
                        <Route path="/dashboard" element={<Navigate to="/" replace />} />
                <Route
                  path="/details/portscan"
                  element={
                    <ProtectedRoute>
                      <PortScanDetails
                        moduleState={moduleData.portscan}
                        updateModuleState={(patch) => updateModuleData("portscan", patch)}
                      />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/details/honeypot"
                  element={
                    <ProtectedRoute>
                      <HoneypotDetails
                        moduleState={moduleData.honeypot}
                        updateModuleState={(patch) => updateModuleData("honeypot", patch)}
                      />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/details/darkweb"
                  element={
                    <ProtectedRoute>
                      <DarkWebDetails />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/details/ransomware"
                  element={
                    <ProtectedRoute>
                      <RansomwareDetails
                        moduleState={moduleData.ransomware}
                        updateModuleState={(patch) => updateModuleData("ransomware", patch)}
                      />
                    </ProtectedRoute>
                  }
                />
              </Routes>
            </main>

            <AlertsPanel alerts={alerts} setAlerts={setAlerts} />
          </div>
        </div>
              }
            />
          </Routes>
        </>
      )}
    </>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
