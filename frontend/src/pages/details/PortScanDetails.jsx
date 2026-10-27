import { useEffect, useState, useRef } from "react";
import { scanSystemPorts } from "../../services/api";

// ── Risk colours (Critical / High / Medium / Low) ─────────────────────────────
const RISK = {
  CRITICAL: { color: "#ff4444", bg: "#ff444420", border: "#c62828", dot: "#ff4444" },
  HIGH:     { color: "#ff6b35", bg: "#ff6b3520", border: "#bf360c", dot: "#ff6b35" },
  MEDIUM:   { color: "#ff9800", bg: "#ff980020", border: "#e65100", dot: "#ff9800" },
  LOW:      { color: "#4caf50", bg: "#4caf5020", border: "#2e7d32", dot: "#4caf50" },
};
const rk = (r) => RISK[(r || "LOW").toUpperCase()] || RISK.LOW;

const normalizeRisk = (value, fallback = "Low") => {
  if (!value || typeof value !== "string") return fallback;
  const upper = value.toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(upper)) {
    return upper[0] + upper.slice(1).toLowerCase();
  }
  return fallback;
};

const normalizeCvss = (value, fallback = null) => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const n = Number.parseFloat(value);
    if (Number.isFinite(n)) return n;
  }
  return fallback;
};

const inferLocalOS = () => {
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes("windows")) return "Windows (Local Host)";
  if (ua.includes("mac os") || ua.includes("macintosh")) return "macOS (Local Host)";
  if (ua.includes("linux")) return "Linux (Local Host)";
  return "Local Host OS";
};

// ── Status config ─────────────────────────────────────────────────────────────
const STATUS = {
  idle:     { label: "IDLE",          color: "#555",    dot: "#555" },
  scanning: { label: "SCANNING...",   color: "#7c83fd", dot: "#7c83fd" },
  complete: { label: "SCAN COMPLETE", color: "#4caf50", dot: "#4caf50" },
  error:    { label: "ERROR",         color: "#ff4444", dot: "#ff4444" },
};

// ── Animated scan progress bar ────────────────────────────────────────────────
function ProgressBar({ active }) {
  const [pct, setPct] = useState(0);
  const ref = useRef(null);

  const prevActive = useRef(false);
  if (active && !prevActive.current) {
    setPct(5);
    clearInterval(ref.current);
    ref.current = setInterval(() => {
      setPct(prev => prev >= 88 ? 88 : prev + Math.random() * 2);
    }, 700);
  }
  if (!active && prevActive.current) {
    clearInterval(ref.current);
    setPct(0);
  }
  prevActive.current = active;

  if (!active && pct === 0) return null;

  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "#666", marginBottom: 4 }}>
        <span>Scan Progress</span>
        <span>{Math.round(pct)}%</span>
      </div>
      <div style={{ height: 6, background: "#2a2a3a", borderRadius: 3, overflow: "hidden" }}>
        <div style={{
          height: "100%", background: "linear-gradient(90deg, #7c83fd, #26c6da)",
          borderRadius: 3, width: `${pct}%`,
          transition: "width 0.5s ease",
          boxShadow: "0 0 8px #7c83fd88",
        }} />
      </div>
    </div>
  );
}

// ── Spinner ───────────────────────────────────────────────────────────────────
function Spinner() {
  return (
    <span style={{
      display: "inline-block", width: 14, height: 14,
      border: "2px solid #333", borderTop: "2px solid #7c83fd",
      borderRadius: "50%", animation: "pspin .7s linear infinite",
      marginRight: 8, verticalAlign: "middle",
    }}>
      <style>{`@keyframes pspin{to{transform:rotate(360deg)}}`}</style>
    </span>
  );
}

// ── Status indicator pill ─────────────────────────────────────────────────────
function StatusPill({ status }) {
  const s = STATUS[status] || STATUS.idle;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
      <span style={{
        width: 8, height: 8, borderRadius: "50%",
        background: s.dot,
        boxShadow: status === "scanning" ? `0 0 6px ${s.dot}` : "none",
        animation: status === "scanning" ? "pulse 1s ease-in-out infinite" : "none",
      }} />
      <span style={{ fontSize: 12, fontWeight: 700, color: s.color, letterSpacing: 1 }}>
        {s.label}
      </span>
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}`}</style>
    </div>
  );
}

// ── Overview stat card ────────────────────────────────────────────────────────
function StatCard({ label, value, color, sub }) {
  return (
    <div style={{
      flex: "1 1 110px", background: "#1a1a2e",
      border: `1px solid ${color}40`, borderRadius: 10,
      padding: "14px 18px", textAlign: "center",
    }}>
      <div style={{ fontSize: 26, fontWeight: 800, color }}>{value}</div>
      <div style={{ fontSize: 11, color: "#aaa", marginTop: 3 }}>{label}</div>
      {sub && <div style={{ fontSize: 10, color: "#555", marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

// ── Security score ring ───────────────────────────────────────────────────────
function ScoreRing({ score, tier }) {
  const r = 36, circ = 2 * Math.PI * r;
  const fill = circ - (score / 100) * circ;
  const riskColor = tier === "Critical" ? "#ff4444" : tier === "High" ? "#ff6b35" : tier === "Medium" ? "#ff9800" : "#4caf50";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
      <svg width={90} height={90}>
        <circle cx={45} cy={45} r={r} fill="none" stroke="#2a2a3a" strokeWidth={8} />
        <circle cx={45} cy={45} r={r} fill="none" stroke={riskColor} strokeWidth={8}
          strokeDasharray={circ} strokeDashoffset={fill}
          strokeLinecap="round" transform="rotate(-90 45 45)"
          style={{ transition: "stroke-dashoffset 1s ease" }} />
        <text x={45} y={49} textAnchor="middle" fill={riskColor} fontSize={16} fontWeight={800}>{score}</text>
      </svg>
      <div>
        <div style={{ fontSize: 12, color: "#888" }}>Security Score</div>
        <div style={{ fontSize: 18, fontWeight: 700, color: riskColor, marginTop: 2 }}>{tier} Risk</div>
        <div style={{ fontSize: 11, color: "#555", marginTop: 2 }}>out of 100</div>
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function PortScanDetails({ moduleState, updateModuleState }) {
  const [status, setStatus]           = useState("idle");
  const [scanData, setScanData]       = useState(null);
  const [error, setError]             = useState("");
  const [scanning, setScanning]       = useState(false);
  const [lastScan, setLastScan]       = useState(null);
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [deepReporting, setDeepReporting] = useState(false);
  const [deepReport, setDeepReport]   = useState(null);

  useEffect(() => {
    if (!moduleState) return;
    if (moduleState.scanData) {
      setScanData(moduleState.scanData);
      setLastScan(
        moduleState.lastScan
          ? new Date(moduleState.lastScan).toLocaleString()
          : null
      );
      setStatus(moduleState.status === "IDLE" ? "idle" : "complete");
    }
  }, [moduleState]);

  // Toggle port row expansion
  const toggleExpanded = (port) => {
    const newSet = new Set(expandedRows);
    if (newSet.has(port)) {
      newSet.delete(port);
    } else {
      newSet.add(port);
    }
    setExpandedRows(newSet);
  };

  // Generate deep report
  const generateDeepReport = async () => {
    if (!scanData?.dashboard?.[0]) return;
    
    setDeepReporting(true);
    try {
      // Deep report feature not yet implemented in unified backend
      // For now, generate a summary from existing scan data
      const dash = scanData.dashboard[0];
      setDeepReport({
        summary: `Security scan of ${dash.host} found ${dash.total_ports} open ports.`,
        risk_assessment: `Overall risk level: ${dash.risk_tier}`,
        recommendations: dash.high_port_count > 0 
          ? "Close unnecessary high-risk ports and review firewall rules."
          : "System appears secure. Continue monitoring.",
      });
    } catch (e) {
      setError(`Failed to generate deep report: ${e.message}`);
    }
    setDeepReporting(false);
  };

  // Export to PDF
  const exportPDF = () => {
    const content = `
AI Port Scan Security Assessment Report
========================================

System: ${scanData?.dashboard?.[0]?.host}
OS: ${scanData?.dashboard?.[0]?.operating_system}
Security Score: ${scanData?.dashboard?.[0]?.security_score}
Risk Tier: ${scanData?.dashboard?.[0]?.risk_tier}
Final Risk: ${scanData?.dashboard?.[0]?.final_risk}

Open Ports: ${scanData?.dashboard?.[0]?.total_ports}
Critical Ports: ${scanData?.dashboard?.[0]?.critical_port_count}
High Risk Ports: ${scanData?.dashboard?.[0]?.high_port_count}

Generated: ${new Date().toLocaleString()}
    `;
    
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `port-scan-report-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const runScan = async () => {
    setScanning(true);
    setStatus("scanning");
    setError("");
    setScanData(null);

    try {
      const data = await scanSystemPorts();

      if (data.status === "error" || data.error) {
        setError(data.message || data.error || "Scan failed.");
        setStatus("error");
      } else if (!data.dashboard?.length) {
        setError("No hosts found in scan result.");
        setStatus("error");
      } else {
        setScanData(data);
        setLastScan(data.timestamp ? new Date(data.timestamp).toLocaleString() : new Date().toLocaleString());
        setStatus("complete");

        const dashEntry = data?.dashboard?.[0] || {};
        const count = Number(dashEntry.total_ports ?? (Array.isArray(dashEntry.open_ports) ? dashEntry.open_ports.length : 0));
        const risk = String(dashEntry.final_risk || dashEntry.risk_tier || "LOW").toUpperCase();

        updateModuleState({
          count,
          status: risk !== "LOW" && risk !== "SAFE" ? "MALICIOUS" : "SAFE",
          scanData: data,
          lastScan: new Date().toISOString(),
        });
      }
    } catch (e) {
      setError(`Port scan failed: ${e.message}. Is the backend running?`);
      setStatus("error");
    }

    setScanning(false);
  };

  // Extract dashboard + report for the first (only) host
  const dash   = scanData?.dashboard?.[0];
  const report = scanData?.report?.[0];
  const openPorts = Array.isArray(dash?.open_ports) ? dash.open_ports : [];
  const reportPortAnalysis = Array.isArray(report?.port_analysis) ? report.port_analysis : [];

  const portAnalysisMap = new Map(
    reportPortAnalysis.map((entry) => [Number(entry?.port), entry])
  );

  const allOpenPortRows = openPorts.map((rawPort) => {
    const port = Number(rawPort);
    const known = portAnalysisMap.get(port);

    const service =
      known?.service ||
      known?.service_name ||
      `Port-${port}`;

    const riskLevel = normalizeRisk(
      known?.risk_level || known?.risk || "Low",
      "Low"
    );

    const cvssScore = normalizeCvss(
      known?.cvss_score ?? known?.cvss ?? known?.score,
      null
    );

    const exploitability =
      known?.exploitability || known?.exploit || "Unknown";

    const mitigationPriority =
      known?.mitigation_priority || known?.priority || "Medium";

    return {
      ...known,
      port,
      service,
      risk_level: riskLevel,
      cvss_score: cvssScore,
      exploitability,
      mitigation_priority: mitigationPriority,
    };
  });

  const detectedOS = dash?.operating_system || report?.operating_system || "Unknown";
  const isLocalTarget = ["127.0.0.1", "localhost", "::1"].includes((dash?.host || "").toLowerCase());
  const displayOS =
    (!detectedOS || detectedOS.toLowerCase() === "unknown") && isLocalTarget
      ? inferLocalOS()
      : (detectedOS || "Unknown");

  return (
    <div className="report-page" style={{ color: "#e0e0e0" }}>

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12, marginBottom: 28 }}>
        <div>
          <h1 style={{ marginBottom: 4 }}>AI Port Scan Analyzer</h1>
          <p style={{ color: "#888", fontSize: 13, margin: 0 }}>
            ML-powered localhost port risk analysis — XGBoost + port intelligence
          </p>
        </div>
        <StatusPill status={status} />
      </div>

      {/* ── Scan button row ──────────────────────────────────────────────────── */}
      <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 24, flexWrap: "wrap" }}>
        <button
          className="scan-btn"
          onClick={runScan}
          disabled={scanning}
          style={{ minWidth: 180, fontSize: 14, display: "flex", alignItems: "center", justifyContent: "center" }}
        >
          {scanning && <Spinner />}
          {scanning ? "Scanning System…" : "Scan System Ports"}
        </button>

        {scanData && (
          <button
            className="scan-btn"
            onClick={runScan}
            disabled={scanning}
            style={{ background: "#1a2a4a", minWidth: 140 }}
          >
            ↻ Refresh Scan
          </button>
        )}

        {scanData && (
          <button
            className="scan-btn"
            onClick={generateDeepReport}
            disabled={deepReporting}
            style={{ background: "#2a4a1a", minWidth: 160 }}
            title="Generate comprehensive security assessment with attack scenarios and mitigation strategies"
          >
            {deepReporting ? "Generating…" : "📊 Deep Report"}
          </button>
        )}

        {scanData && (
          <button
            className="scan-btn"
            onClick={exportPDF}
            disabled={scanning || deepReporting}
            style={{ background: "#1a2a4a", minWidth: 120 }}
            title="Export scan results to file"
          >
            ⬇️ Export
          </button>
        )}

        {lastScan && (
          <span style={{ fontSize: 12, color: "#555" }}>
            Last scan: <span style={{ color: "#888" }}>{lastScan}</span>
          </span>
        )}
      </div>

      {/* ── Progress bar ─────────────────────────────────────────────────────── */}
      <ProgressBar active={scanning} />

      {/* ── Error ────────────────────────────────────────────────────────────── */}
      {error && (
        <div style={{
          background: "#2a0a0a", border: "1px solid #c62828",
          borderRadius: 8, padding: "12px 18px", marginBottom: 20,
          color: "#ff6b6b", fontSize: 13,
        }}>
          {error}
        </div>
      )}

      {/* ── Results ──────────────────────────────────────────────────────────── */}
      {dash && (
        <>
          {/* ── Top summary row ─────────────────────────────────────────────── */}
          <div style={{ display: "flex", gap: 20, marginBottom: 24, flexWrap: "wrap", alignItems: "center" }}>
            <ScoreRing score={dash.security_score} tier={dash.risk_tier} />

            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", flex: 1 }}>
              <StatCard label="Open Ports"     value={dash.total_ports}          color="#7c83fd" />
              <StatCard label="Blocked Ports"  value={Math.max(0, 65535 - dash.total_ports)} color="#4caf50" />
              <StatCard label="Critical Ports" value={dash.critical_port_count}  color="#ff4444" />
              <StatCard label="High Risk"      value={dash.high_port_count}      color="#ff6b35" />
              <div title={`OS Accuracy: ${report?.os_accuracy || 'N/A'}% | Device Type: ${report?.os_device_type || 'general'}`}>
                <StatCard label="OS" value={displayOS} color="#26c6da" />
              </div>
            </div>
          </div>

          {/* ── ML prediction badge ─────────────────────────────────────────── */}
          <div style={{
            display: "flex", gap: 16, flexWrap: "wrap",
            background: "#12121e", border: "1px solid #2a2a3a",
            borderRadius: 10, padding: "14px 20px", marginBottom: 20,
            alignItems: "center",
          }}>
            <div>
              <span style={{ fontSize: 11, color: "#666" }}>FINAL RISK</span>
              <div>
                <span style={{
                  ...rk(dash.final_risk),
                  background: rk(dash.final_risk).bg,
                  border: `1px solid ${rk(dash.final_risk).border}`,
                  color: rk(dash.final_risk).color,
                  padding: "4px 14px", borderRadius: 10,
                  fontSize: 13, fontWeight: 800, letterSpacing: 1,
                  display: "inline-block", marginTop: 4,
                }}>
                  {dash.final_risk?.toUpperCase()}
                </span>
              </div>
            </div>
            <div style={{ borderLeft: "1px solid #2a2a3a", paddingLeft: 16 }}>
              <span style={{ fontSize: 11, color: "#666" }}>RISK SCORE</span>
              <div style={{ fontSize: 20, fontWeight: 700, color: "#7c83fd" }}>{dash.risk_score?.toFixed(1)}%</div>
            </div>
            <div style={{ borderLeft: "1px solid #2a2a3a", paddingLeft: 16 }}>
              <span style={{ fontSize: 11, color: "#666" }}>ML CONFIDENCE</span>
              <div style={{ fontSize: 20, fontWeight: 700, color: "#26c6da" }}>{dash.confidence?.toFixed(1)}%</div>
            </div>
            {report?.ml_prediction && (
              <div style={{ borderLeft: "1px solid #2a2a3a", paddingLeft: 16 }}>
                <span style={{ fontSize: 11, color: "#666" }}>ALGORITHM</span>
                <div style={{ fontSize: 12, color: "#aaa", marginTop: 4 }}>{report.ml_prediction.algorithm}</div>
              </div>
            )}
            {report?.hybrid_logic?.escalation_applied && (
              <div style={{
                marginLeft: "auto", background: "#ff980018",
                border: "1px solid #e65100", borderRadius: 8,
                padding: "6px 12px", fontSize: 11, color: "#ff9800",
              }}>
                Port intelligence escalation applied
              </div>
            )}
          </div>

          {/* ── Port analysis table ─────────────────────────────────────────── */}
          {allOpenPortRows.length > 0 && (
            <div style={{
              background: "#12121e", border: "1px solid #2a2a3a",
              borderRadius: 10, marginBottom: 20,
            }}>
              <div style={{
                padding: "14px 20px", borderBottom: "1px solid #2a2a3a",
                display: "flex", justifyContent: "space-between", alignItems: "center",
              }}>
                <h2 style={{ margin: 0, fontSize: 15, color: "#ddd" }}>Port Analysis — {dash.host}</h2>
                <span style={{ fontSize: 12, color: "#555" }}>
                  {allOpenPortRows.length} port{allOpenPortRows.length !== 1 ? "s" : ""} open
                </span>
              </div>

              {/* Scrollable table wrapper with fixed height */}
              <div className="port-table-scroll">
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                  <thead style={{ 
                    position: "sticky", 
                    top: 0, 
                    zIndex: 10,
                  }}>
                    <tr style={{ background: "#1a1a2e", color: "#888" }}>
                      {["Risk", "Port", "Service", "Risk Level", "CVSS", "Exploitability", "Priority"].map(h => (
                        <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontWeight: 600, whiteSpace: "nowrap", background: "#1a1a2e" }}>
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {allOpenPortRows
                      .slice()
                      .sort((a, b) => {
                        const ord = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
                        return (ord[(a.risk_level || "LOW").toUpperCase()] ?? 4) - (ord[(b.risk_level || "LOW").toUpperCase()] ?? 4);
                      })
                      .map((p, i) => {
                        const r = rk(p.risk_level);
                        const isExpanded = expandedRows.has(p.port);
                        return [
                            <tr key={`row-${p.port}`} style={{
                              background: i % 2 === 0 ? "#12121e" : "#161624",
                              borderLeft: `4px solid ${r.border}`,
                              cursor: "pointer",
                              transition: "background 0.2s",
                            }}
                            onClick={() => toggleExpanded(p.port)}
                            onMouseEnter={(e) => e.currentTarget.style.background = "rgba(0,255,100,0.05)"}
                            onMouseLeave={(e) => e.currentTarget.style.background = i % 2 === 0 ? "#12121e" : "#161624"}
                            >
                              <td style={{ padding: "10px 16px" }}>
                                <span style={{
                                  display: "inline-block", width: 10, height: 10,
                                  borderRadius: "50%", background: r.dot,
                                  boxShadow: `0 0 5px ${r.dot}88`,
                                }} />
                              </td>
                              <td style={{ padding: "10px 16px", fontWeight: 700, color: "#7c83fd", fontSize: 14 }}>
                                <span style={{ marginRight: 8 }}>{isExpanded ? "▼" : "▶"}</span>
                                {p.port}
                              </td>
                              <td style={{ padding: "10px 16px", color: "#ccc" }}>{p.service}</td>
                              <td style={{ padding: "10px 16px" }}>
                                <span style={{
                                  background: r.bg, border: `1px solid ${r.border}`,
                                  color: r.color, padding: "3px 10px", borderRadius: 10,
                                  fontSize: 11, fontWeight: 700, letterSpacing: 1,
                                }}>
                                  {p.risk_level?.toUpperCase()}
                                </span>
                              </td>
                              <td style={{ padding: "10px 16px", color: p.cvss_score >= 7 ? "#ff4444" : p.cvss_score >= 4 ? "#ff9800" : "#4caf50", fontWeight: 600 }}>
                                {typeof p.cvss_score === "number" ? p.cvss_score.toFixed(1) : "N/A"}
                              </td>
                              <td style={{ padding: "10px 16px", color: "#aaa" }}>{p.exploitability || "—"}</td>
                              <td style={{ padding: "10px 16px", color: "#aaa" }}>{p.mitigation_priority || "—"}</td>
                            </tr>
                            ,
                            isExpanded && (
                              <tr key={`expanded-${p.port}`} style={{ background: "#0a0a12", borderLeft: `4px solid ${r.color}` }}>
                                <td colSpan="7" style={{ padding: "12px 16px" }}>
                                  <div style={{ display: "flex", gap: 24, fontSize: 13, flexWrap: "wrap" }}>
                                    {p.product && <div><span style={{ color: "#666" }}>Product:</span> <span style={{ color: "#aaa" }}>{p.product}</span></div>}
                                    {p.version && <div><span style={{ color: "#666" }}>Version:</span> <span style={{ color: "#aaa" }}>{p.version}</span></div>}
                                    {p.explanation && <div><span style={{ color: "#666" }}>Explanation:</span> <span style={{ color: "#aaa", maxWidth: 400 }}>{p.explanation}</span></div>}
                                  </div>
                                </td>
                              </tr>
                            )
                        ];
                      })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── No known ports ───────────────────────────────────────────────── */}
          {allOpenPortRows.length === 0 && dash.total_ports > 0 && (
            <div style={{
              background: "#1a1a2e", borderRadius: 10, padding: "20px",
              color: "#666", border: "1px solid #2a2a3a", marginBottom: 20,
              fontSize: 13,
            }}>
              {dash.total_ports} port(s) open but none matched the port intelligence database. All classified as Low risk.
            </div>
          )}

          {/* ── Recommendations ─────────────────────────────────────────────── */}
          {dash.recommendations?.length > 0 && (
            <div style={{
              background: "#12121e", border: "1px solid #2a2a3a",
              borderRadius: 10, padding: "18px 22px", marginBottom: 20,
            }}>
              <h2 style={{ margin: "0 0 14px", fontSize: 15, color: "#ddd" }}>Recommendations</h2>
              <ul style={{ margin: 0, padding: 0, listStyle: "none", maxHeight: 180, overflowY: "auto" }}>
                {dash.recommendations.map((rec, i) => {
                  const isCrit = rec.startsWith("CRITICAL");
                  return (
                    <li key={i} style={{
                      display: "flex", alignItems: "flex-start", gap: 10,
                      padding: "8px 0",
                      borderBottom: i < dash.recommendations.length - 1 ? "1px solid #1e1e2e" : "none",
                    }}>
                      <span style={{
                        width: 6, height: 6, borderRadius: "50%", marginTop: 6, flexShrink: 0,
                        background: isCrit ? "#ff4444" : "#ff9800",
                      }} />
                      <span style={{ fontSize: 13, color: isCrit ? "#ff8888" : "#ccc" }}>{rec}</span>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          {/* ── Active services ─────────────────────────────────────────────── */}
          {dash.active_services?.length > 0 && (
            <div style={{
              background: "#12121e", border: "1px solid #2a2a3a",
              borderRadius: 10, padding: "14px 20px", marginBottom: 20,
            }}>
              <h2 style={{ margin: "0 0 10px", fontSize: 15, color: "#ddd" }}>Active Services</h2>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", maxHeight: 120, overflowY: "auto" }}>
                {allOpenPortRows.map((svc, i) => (
                  <span key={i} style={{
                    background: "#1a1a2e", border: "1px solid #3a3a4a",
                    borderRadius: 6, padding: "4px 12px",
                    fontSize: 12, color: "#26c6da",
                  }}>
                    {svc.port}/{svc.service}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* ── Explainable AI - SHAP Feature Importance ──────────────────────── */}
          {report?.explainability && (
            <div style={{
              background: "#12121e", border: "1px solid #2a2a3a",
              borderRadius: 10, overflow: "hidden", marginBottom: 20,
            }}>
              <div style={{
                padding: "14px 20px", borderBottom: "1px solid #2a2a3a",
                display: "flex", justifyContent: "space-between", alignItems: "center",
              }}>
                <h2 style={{ margin: 0, fontSize: 15, color: "#ddd" }}>🤖 Explainable AI — Feature Importance (SHAP)</h2>
                <span style={{ fontSize: 11, color: "#666", fontWeight: 600 }}>XGBoost Analysis</span>
              </div>
              
              {/* Top 5 Features */}
              <div style={{ padding: "18px 20px", maxHeight: 520, overflowY: "auto" }}>
                <div style={{ marginBottom: 16 }}>
                  <h3 style={{ margin: "0 0 12px", fontSize: 13, color: "#aaa", textTransform: "uppercase", letterSpacing: 1 }}>
                    Top Risk Factors
                  </h3>
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {report.explainability.top_features?.slice(0, 5).map((feat, i) => {
                      const isRiskIncreasing = feat.impact === "increases_risk";
                      const impactColor = isRiskIncreasing ? "#ff6b35" : "#4caf50";
                      const impactLabel = isRiskIncreasing ? "↑ Increases Risk" : "↓ Decreases Risk";
                      return (
                        <div key={i} style={{
                          background: "#15151f", border: `1px solid ${impactColor}44`,
                          borderRadius: 8, padding: "10px 14px",
                          display: "flex", justifyContent: "space-between", alignItems: "center",
                        }}>
                          <div>
                            <div style={{ fontSize: 12, fontWeight: 700, color: "#ddd", marginBottom: 4 }}>
                              {i + 1}. {feat.feature.replace(/_/g, " ").toUpperCase()}
                            </div>
                            <div style={{ fontSize: 11, color: "#888" }}>
                              SHAP Value: <span style={{ color: impactColor, fontWeight: 600 }}>{feat.shap_value.toFixed(4)}</span>
                            </div>
                          </div>
                          <span style={{
                            background: impactColor + "20", color: impactColor,
                            border: `1px solid ${impactColor}60`, borderRadius: 6,
                            padding: "4px 8px", fontSize: 11, fontWeight: 600, whiteSpace: "nowrap",
                          }}>
                            {impactLabel}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Feature Explanations */}
                {report.feature_analysis?.human_explanations?.length > 0 && (
                  <div style={{ 
                    borderTop: "1px solid #2a2a3a", paddingTop: 16,
                    marginTop: 16,
                  }}>
                    <h3 style={{ margin: "0 0 12px", fontSize: 13, color: "#aaa", textTransform: "uppercase", letterSpacing: 1 }}>
                      Risk Factor Analysis
                    </h3>
                    <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
                      {report.feature_analysis.human_explanations.map((exp, i) => (
                        <li key={i} style={{
                          display: "flex", alignItems: "flex-start", gap: 10,
                          padding: "8px 0",
                          borderBottom: i < report.feature_analysis.human_explanations.length - 1 ? "1px solid #1e1e2e" : "none",
                        }}>
                          <span style={{
                            width: 6, height: 6, borderRadius: "50%", marginTop: 6, flexShrink: 0,
                            background: "#7c83fd",
                          }} />
                          <span style={{ fontSize: 13, color: "#bbb" }}>{exp}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* All Features Detail (Expandable concept) */}
              {report.explainability.all_features?.length > 5 && (
                <div style={{ 
                  padding: "0 20px 14px",
                  borderTop: "1px solid #2a2a3a",
                }}>
                  <details style={{ cursor: "pointer" }}>
                    <summary style={{
                      fontSize: 12, color: "#7c83fd", fontWeight: 600, padding: "8px 0",
                      userSelect: "none",
                    }}>
                      📊 View All {report.explainability.all_features.length} Features
                    </summary>
                    <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 8 }}>
                      {report.explainability.all_features.slice(5).map((feat, i) => (
                        <div key={i} style={{
                          background: "#15151f", border: "1px solid #2a2a3a",
                          borderRadius: 6, padding: "8px 12px",
                          display: "flex", justifyContent: "space-between", alignItems: "center",
                          fontSize: 11,
                        }}>
                          <span style={{ color: "#888" }}>{feat.feature.replace(/_/g, " ")}</span>
                          <span style={{ color: "#7c83fd", fontWeight: 600 }}>{feat.shap_value.toFixed(4)}</span>
                        </div>
                      ))}
                    </div>
                  </details>
                </div>
              )}
            </div>
          )}

          {/* ── Security Score Justification ──────────────────────────────────── */}
          {report?.justification && (
            <div style={{
              background: "#12121e", border: "1px solid #2a2a3a",
              borderRadius: 10, padding: "14px 20px", marginBottom: 20,
            }}>
              <h2 style={{ margin: "0 0 10px", fontSize: 15, color: "#ddd" }}>Assessment Justification</h2>
              <p style={{ margin: 0, fontSize: 13, color: "#aaa", lineHeight: 1.6 }}>
                {report.justification}
              </p>
            </div>
          )}
        </>
      )}

      {/* ── Deep Report ──────────────────────────────────────────────────────── */}
      {deepReport && (
        <div style={{
          background: "#12121e", border: "1px solid #2a2a3a",
          borderRadius: 10, padding: "20px", marginBottom: 20,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <h2 style={{ margin: 0, fontSize: 16, color: "#26c6da" }}>🔬 Deep Security Assessment</h2>
            <button
              onClick={() => setDeepReport(null)}
              style={{ background: "none", border: "none", color: "#666", cursor: "pointer", fontSize: 16 }}
            >
              ✕
            </button>
          </div>

          {deepReport.system_overview && (
            <div style={{ marginBottom: 16, fontSize: 13, color: "#aaa", lineHeight: 1.6 }}>
              <strong style={{ color: "#ddd" }}>System Overview:</strong><br />
              {deepReport.system_overview.summary}
            </div>
          )}

          {deepReport.port_analysis?.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <strong style={{ color: "#ddd", fontSize: 13 }}>Port-Wise Analysis:</strong>
              <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 8, maxHeight: 300, overflowY: "auto" }}>
                {deepReport.port_analysis.slice(0, 5).map((port, i) => (
                  <div key={i} style={{
                    background: "#0a0a12", border: `1px solid ${rk(port.risk_level).border}`,
                    borderRadius: 6, padding: "10px", fontSize: 12,
                  }}>
                    <div style={{ color: rk(port.risk_level).color, fontWeight: 600 }}>
                      Port {port.port} - {port.service} ({port.risk_level})
                    </div>
                    {port.cons?.length > 0 && (
                      <div style={{ color: "#ff6b6b", marginTop: 4, fontSize: 11 }}>
                        ⚠️ {port.cons[0]}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {deepReport.attack_scenarios?.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <strong style={{ color: "#ff9800", fontSize: 13 }}>Attack Scenarios:</strong>
              <div style={{ marginTop: 8, fontSize: 12, color: "#aaa" }}>
                {deepReport.attack_scenarios[0]?.scenarios?.slice(0, 2).map((scenario, i) => (
                  <div key={i} style={{ marginBottom: 6 }}>
                    • {scenario.name} ({scenario.likelihood})
                  </div>
                ))}
              </div>
            </div>
          )}

          {deepReport.mitigation?.immediate_actions && (
            <div style={{ marginBottom: 16 }}>
              <strong style={{ color: "#4caf50", fontSize: 13 }}>Immediate Actions:</strong>
              <ul style={{ margin: 8, paddingLeft: 20, fontSize: 12, color: "#aaa", lineHeight: 1.5 }}>
                {deepReport.mitigation.immediate_actions.slice(0, 3).map((action, i) => (
                  <li key={i}>{action}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* ── No ports found ───────────────────────────────────────────────────── */}
      {dash && dash.total_ports === 0 && (
        <div style={{
          background: "#1a1a2e", borderRadius: 10, padding: "30px",
          textAlign: "center", color: "#555", border: "1px solid #2a2a3a",
        }}>
          <div style={{ fontSize: 32, marginBottom: 10 }}>&#9989;</div>
          <div style={{ fontSize: 14 }}>No open ports detected on localhost.</div>
          <div style={{ fontSize: 12, color: "#444", marginTop: 6 }}>System appears to have no exposed services.</div>
        </div>
      )}

      {/* ── Idle empty state ─────────────────────────────────────────────────── */}
      {status === "idle" && (
        <div style={{ textAlign: "center", color: "#444", marginTop: 60, fontSize: 14 }}>
          <div style={{ fontSize: 44, marginBottom: 14 }}>&#128270;</div>
          <div style={{ fontSize: 15, color: "#666" }}>
            Click <strong style={{ color: "#7c83fd" }}>Scan System Ports</strong> to analyse localhost.
          </div>
          <div style={{ fontSize: 12, color: "#444", marginTop: 8 }}>
            Runs <code style={{ color: "#888" }}>nmap -sV --open 127.0.0.1</code> and classifies each port using XGBoost + port intelligence.
          </div>
        </div>
      )}
    </div>
  );
}
