"""
Report generator — creates comprehensive deep reports
Includes system overview, port analysis, attack scenarios, security recommendations
"""

from typing import Dict, List, Any
from datetime import datetime

class DeepReportGenerator:
    """Generate comprehensive security assessment reports"""
    
    @staticmethod
    def generate_deep_report(
        dashboard: Dict[str, Any],
        report: Dict[str, Any],
        attack_scenarios: Dict[str, Any],
        ports_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive deep report including:
        - System overview
        - Port-wise analysis with pros/cons
        - Attack scenarios
        - Mitigation steps
        - Overall risk score with justification
        """
        
        deep_report = {
            "timestamp": datetime.now().isoformat(),
            "scan_id": dashboard.get("host", "unknown"),
            
            # SYSTEM OVERVIEW
            "system_overview": {
                "host": dashboard["host"],
                "os": dashboard.get("operating_system", "Unknown"),
                "total_ports": dashboard.get("total_ports", 0),
                "critical_ports": dashboard.get("critical_port_count", 0),
                "high_risk_ports": dashboard.get("high_port_count", 0),
                "security_score": dashboard.get("security_score", 0),
                "risk_tier": dashboard.get("risk_tier", "Unknown"),
                "final_risk": dashboard.get("final_risk", "Unknown"),
                "summary": DeepReportGenerator._generate_system_summary(dashboard)
            },
            
            # PORT-WISE ANALYSIS
            "port_analysis": DeepReportGenerator._analyze_ports(report.get("port_analysis", []), ports_data),
            
            # ATTACK SCENARIOS
            "attack_scenarios": attack_scenarios,
            
            # MITIGATION STRATEGIES
            "mitigation": DeepReportGenerator._generate_mitigation_strategies(
                dashboard, 
                report.get("port_analysis", [])
            ),
            
            # OVERALL ASSESSMENT
            "assessment": {
                "overall_risk_score": dashboard.get("risk_score", 0),
                "confidence": dashboard.get("confidence", 0),
                "reasoning": DeepReportGenerator._justify_risk_assessment(dashboard, report),
                "action_items": DeepReportGenerator._generate_action_items(dashboard, report.get("port_analysis", []))
            }
        }
        
        return deep_report
    
    @staticmethod
    def _generate_system_summary(dashboard: Dict[str, Any]) -> str:
        """Generate human-readable system summary"""
        summary = f"System {dashboard['host']} running {dashboard.get('operating_system', 'unknown OS')} "
        summary += f"with {dashboard['total_ports']} open ports. "
        
        if dashboard.get("critical_port_count", 0) > 0:
            summary += f"CRITICAL: {dashboard['critical_port_count']} critical services exposed. "
        
        if dashboard.get("high_port_count", 0) > 0:
            summary += f"WARNING: {dashboard['high_port_count']} high-risk services. "
        
        summary += f"Security score: {dashboard['security_score']}/100 ({dashboard.get('risk_tier', 'Unknown')} risk)."
        
        return summary
    
    @staticmethod
    def _analyze_ports(port_analysis: List[Dict[str, Any]], ports_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detailed per-port security analysis"""
        port_details = []
        
        # Create mapping from ports_data
        ports_map = {p["port"]: p for p in ports_data}
        
        for port_info in port_analysis:
            port_num = port_info.get("port", 0)
            service = port_info.get("service", "Unknown")
            risk_level = port_info.get("risk_level", "Low")
            cvss = port_info.get("cvss_score", "N/A")
            
            # Get version info from ports_data
            version_info = ports_map.get(port_num, {})
            product = version_info.get("product", None)
            version = version_info.get("version", None)
            
            port_detail = {
                "port": port_num,
                "service": service,
                "product": product,
                "version": version,
                "risk_level": risk_level,
                "cvss_score": cvss,
                "pros": DeepReportGenerator._get_port_pros(port_num, service),
                "cons": DeepReportGenerator._get_port_cons(port_num, service, risk_level),
                "recommendations": DeepReportGenerator._get_port_recommendations(port_num, service, risk_level),
                "explanation": DeepReportGenerator._get_port_explanation(port_num, service, version)
            }
            
            port_details.append(port_detail)
        
        return sorted(port_details, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["risk_level"], 4))
    
    @staticmethod
    def _get_port_pros(port: int, service: str) -> List[str]:
        """Potential positive aspects of a service"""
        pros = {
            22: ["Encrypted remote administration", "Industry standard"],
            53: ["Essential DNS functionality", "Distributed system design"],
            80: ["Standard web service", "User-facing applications"],
            443: ["Encrypted web service", "HTTPS enforces security"],
            123: ["Time synchronization", "Reduces clock skew"],
            5432: ["Open-source database", "Flexible, powerful"],
            3306: ["Popular database solution", "Wide application support"],
        }
        return pros.get(port, [f"{service} is a standard network service"])
    
    @staticmethod
    def _get_port_cons(port: int, service: str, risk_level: str) -> List[str]:
        """Security concerns for a service"""
        cons = {
            21: ["Unencrypted file transfer", "Weak authentication", "Data visible in transit"],
            23: ["No encryption at all", "Credentials transmitted in cleartext", "Obsolete protocol"],
            22: ["SSH is a common attack target", "Brute force attacks common"],
            25: ["Can be used for spam relay", "Information disclosure via banners"],
            53: ["DNS poisoning attacks", "Zone transfer information leaks", "Amplification DDoS"],
            80: ["No encryption", "Man-in-the-middle attacks", "Session hijacking"],
            110: ["Unencrypted authentication", "Session sniffing possible"],
            143: ["Unencrypted by default", "Weak authentication"],
            389: ["Anonymous LDAP binds possible", "Information leakage"],
            445: ["SMBv1 - critical vulnerabilities (EternalBlue)", "Ransomware entry point", "Privilege escalation"],
            139: ["NetBIOS session spoofing", "Information disclosure"],
            3306: ["Authentication bypass possible", "SQL injection", "No encryption by default"],
            3389: ["Brute force target", "Credential theft", "Privilege escalation"],
            5432: ["Default weak authentication", "SQL injection risks"],
            5900: ["Weak VNC authentication", "Remote control access"],
            1433: ["SQL Server-specific exploits", "Information disclosure"],
            2049: ["No built-in authentication", "NFS mounting allows direct filesystem access"],
        }
        
        port_cons = cons.get(port, [f"{service} has standard security concerns"])
        
        if risk_level == "CRITICAL":
            port_cons.insert(0, "CRITICAL VULNERABILITY - Immediate action required")
        elif risk_level == "HIGH":
            port_cons.insert(0, "High-risk service - Strong security controls needed")
        
        return port_cons
    
    @staticmethod
    def _get_port_recommendations(port: int, service: str, risk_level: str) -> List[str]:
        """Security recommendations for a port/service"""
        if risk_level == "CRITICAL":
            return [
                "IMMEDIATELY disable this service if not essential",
                "If required: Update to latest patched version",
                "Restrict access by firewall to authorized IPs only",
                "Monitor aggressively for exploitation attempts"
            ]
        
        elif risk_level == "HIGH":
            return [
                "Restrict access by IP whitelist (firewall/security group)",
                "Use strong authentication (SSH keys, MFA where available)",
                "Keep service patched to latest version",
                "Monitor connections and failed attempts",
                "Consider running on non-standard port"
            ]
        
        elif risk_level == "MEDIUM":
            return [
                "Apply latest security patches",
                "Use encryption where available",
                "Implement least-privilege access controls",
                "Monitor for unusual activity"
            ]
        
        else:  # LOW
            return [
                "Maintain current updates",
                "Regular security monitoring",
                "Standard hardening practices"
            ]
    
    @staticmethod
    def _get_port_explanation(port: int, service: str, version: str = None) -> str:
        """Explain what the port does"""
        explanations = {
            22: "SSH - Secure remote administration protocol. Essential for server management but high-value target.",
            21: "FTP - File transfer. Obsolete; data and credentials transmitted in cleartext. Use SFTP/SCP.",
            23: "Telnet - Unencrypted remote access. CRITICAL: Must be disabled; use SSH instead.",
            25: "SMTP - Mail transmission protocol. Core email service but should only accept from trusted sources.",
            53: "DNS - Domain name resolution. Essential network service. Zone transfers should be restricted.",
            80: "HTTP - Web service (unencrypted). Use HTTPS (port 443) for sensitive content.",
            110: "POP3 - Email retrieval. Deprecated due to unencrypted authentication. Use POP3S.",
            143: "IMAP - Email access protocol. Supports encrypted variant (IMAPS on 993).",
            389: "LDAP - Directory services. Anonymous binds and unauthenticated queries must be disabled.",
            443: "HTTPS - Encrypted web service. Security depends on certificate validity and TLS configuration.",
            445: "SMB - Windows file/printer sharing (NT protocol). High-risk; vulnerable to ransomware and worms.",
            3306: "MySQL - Database server. Should NEVER be internet-exposed. Restrict to internal networks only.",
            3389: "RDP - Windows Remote Desktop. Attractive brute-force target. Use VPN + MFA.",
            5432: "PostgreSQL - Database server. Restrict to internal IPs; no internet exposure.",
            5900: "VNC - Remote display access. Weak authentication; prefer SSH tunneling.",
            1433: "MSSQL - Microsoft SQL Server. High-value target; internal-only access required.",
            2049: "NFS - Network file system. No authentication by default; serious risk if exposed.",
        }
        
        explanation = explanations.get(port, f"{service} on port {port}")
        if version:
            explanation += f" (Version: {version})"
        return explanation
    
    @staticmethod
    def _generate_mitigation_strategies(dashboard: Dict[str, Any], ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate actionable mitigation strategies"""
        strategies = {
            "immediate_actions": [],
            "short_term": [],
            "long_term": []
        }
        
        critical_count = dashboard.get("critical_port_count", 0)
        high_count = dashboard.get("high_port_count", 0)
        
        if critical_count > 0:
            strategies["immediate_actions"].append(
                f"RED ALERT: {critical_count} critical service(s) exposed. Disable or firewall immediately."
            )
        
        if high_count > 0:
            strategies["immediate_actions"].append(
                f"HIGH PRIORITY: {high_count} high-risk service(s). Restrict access by IP whitelist."
            )
        
        strategies["immediate_actions"].append("Enable firewall (Windows Defender, iptables, etc.)")
        strategies["immediate_actions"].append("Block inbound traffic except essential services")
        
        strategies["short_term"].extend([
            "Scan and install all OS/application security updates",
            "Review each open port; disable non-essential services",
            "Implement IP whitelisting for critical services",
            "Configure strong authentication (SSH keys, MFA)",
            "Set up security monitoring/alerts"
        ])
        
        strategies["long_term"].extend([
            "Implement network segmentation (DMZ, internal networks)",
            "Deploy intrusion detection system (IDS/IPS)",
            "Conduct regular security assessments",
            "Establish patch management policy",
            "Train staff on security best practices"
        ])
        
        return strategies
    
    @staticmethod
    def _justify_risk_assessment(dashboard: Dict[str, Any], report: Dict[str, Any]) -> str:
        """Explain why the risk score was assigned"""
        reasons = []
        
        score = dashboard.get("risk_score", 0)
        tier = dashboard.get("risk_tier", "Unknown")
        
        reasons.append(f"Risk score {score}% ({tier} tier) based on:")
        reasons.append(f"- {dashboard.get('total_ports', 0)} open ports (larger surface area = higher risk)")
        reasons.append(f"- {dashboard.get('critical_port_count', 0)} critical services")
        reasons.append(f"- {dashboard.get('high_port_count', 0)} high-risk services")
        
        if report.get("ml_prediction"):
            confidence = report["ml_prediction"].get("confidence", 0)
            reasons.append(f"- ML model confidence: {confidence}%")
        
        if dashboard.get("operating_system"):
            reasons.append(f"- OS: {dashboard['operating_system']} (typical target profile)")
        
        return " ".join(reasons)
    
    @staticmethod
    def _generate_action_items(dashboard: Dict[str, Any], ports: List[Dict[str, Any]]) -> List[str]:
        """Generate prioritized action items"""
        actions = []
        
        # Priority 1: Critical
        critical_ports = [p for p in ports if p.get("risk_level") == "CRITICAL"]
        if critical_ports:
            actions.append(f"[P1-CRITICAL] Disable/firewall {len(critical_ports)} critical port(s): {[p['port'] for p in critical_ports]}")
        
        # Priority 2: High
        high_ports = [p for p in ports if p.get("risk_level") == "HIGH"]
        if high_ports:
            actions.append(f"[P2-HIGH] Restrict access to {len(high_ports)} high-risk port(s)")
        
        # Priority 3: Updates
        actions.append("[P3-MED] Apply all pending security patches to OS & applications")
        
        # Priority 4: Monitoring
        actions.append("[P4-MED] Enable security monitoring (Windows Defender, audit logs)")
        
        # Priority 5: Review
        actions.append("[P5-LOW] Review firewall rules and network policies")
        
        return actions
