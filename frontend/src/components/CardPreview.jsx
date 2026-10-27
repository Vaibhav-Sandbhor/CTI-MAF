import React from "react";

const CardPreview = ({ module, data, color }) => {
  // Format preview data based on module type
  const getPreviewContent = () => {
    switch (module) {
      case "ransomware":
        return {
          title: "Ransomware Summary",
          stats: [
            { label: "Malicious", value: data.summary?.ransomware ?? 0, color: "#ff4444" },
            { label: "Suspicious", value: data.summary?.suspicious ?? 0, color: "#ff9800" },
            { label: "Benign", value: data.summary?.benign ?? 0, color: "#4caf50" },
          ],
        };
      case "portscan":
        // Get port analysis from report for accurate risk counts
        const portAnalysis = data.scanData?.report?.[0]?.port_analysis ?? [];
        const dashboard = data.scanData?.dashboard?.[0] ?? {};
        
        // Count from port_analysis (has risk info) OR use dashboard counts
        const criticalPorts = dashboard.critical_port_count ?? 
          portAnalysis.filter(p => p.risk === "CRITICAL" || p.risk_level === "CRITICAL").length;
        const highRiskPorts = dashboard.high_port_count ?? 
          portAnalysis.filter(p => p.risk === "HIGH" || p.risk_level === "HIGH").length;
        const mediumPorts = dashboard.medium_port_count ?? 
          portAnalysis.filter(p => p.risk === "MEDIUM" || p.risk_level === "MEDIUM").length;
        
        return {
          title: "Port Scan Summary",
          stats: [
            { label: "Critical Ports", value: criticalPorts, color: "#ff4444" },
            { label: "High Risk Ports", value: highRiskPorts, color: "#ff9800" },
            { label: "Medium Risk", value: mediumPorts, color: "#ffc107" },
          ],
        };
      case "honeypot":
        return {
          title: "Honeypot Summary",
          stats: [
            { label: "Total Events", value: data.summary?.total ?? 0, color: "#3b82f6" },
            { label: "Critical", value: data.summary?.critical ?? 0, color: "#ff4444" },
            { label: "Warnings", value: data.summary?.warning ?? 0, color: "#ff9800" },
          ],
        };
      default:
        return { title: "Preview", stats: [] };
    }
  };

  const content = getPreviewContent();

  return (
    <div className="card-preview-popup" style={{ borderColor: color }}>
      <div className="card-preview-header">{content.title}</div>
      <div className="card-preview-stats">
        {content.stats.map((stat, i) => (
          <div key={i} className="card-preview-stat-box">
            <div className="stat-count" style={{ color: stat.color }}>
              {stat.value}
            </div>
            <div className="stat-label">{stat.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default CardPreview;
