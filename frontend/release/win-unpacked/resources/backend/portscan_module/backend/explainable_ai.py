"""
Explainable AI module — provides human-readable reasoning for risk decisions
Generates explanations for port recommendations and overall risk assessment
"""

from typing import Dict, List, Any

class ExplainableAI:
    """Generate human-readable explanations for AI risk decisions"""
    
    @staticmethod
    def explain_port_risk(port: int, service: str, risk_level: str, cvss: float = 0) -> Dict[str, Any]:
        """
        Generate explanation for why a port has a particular risk level
        """
        explanation = {
            "port": port,
            "service": service,
            "risk_level": risk_level,
            "reasoning": [],
            "pros": [],
            "cons": [],
            "recommendations": []
        }
        
        # Risk reasoning
        if risk_level == "CRITICAL":
            explanation["reasoning"].append(f"Port {port} ({service}) is exposed with critical vulnerabilities")
            explanation["cons"].append("Direct attack surface to system resources")
            explanation["cons"].append("High exploitation success rate")
            explanation["recommendations"].append("Immediately disable or firewall this service")
            explanation["recommendations"].append("If needed, restrict access by IP whitelist")
            explanation["recommendations"].append("Update to latest patched version")
        
        elif risk_level == "HIGH":
            explanation["reasoning"].append(f"Port {port} ({service}) provides high-value attack entry point")
            explanation["cons"].append("Common target for attackers")
            explanation["cons"].append("Potential for privilege escalation")
            explanation["recommendations"].append("Restrict access to authorized IPs only")
            explanation["recommendations"].append("Use strong authentication/encryption")
            explanation["recommendations"].append("Monitor for suspicious activity")
        
        elif risk_level == "MEDIUM":
            explanation["reasoning"].append(f"Port {port} ({service}) presents moderate risk if misconfigured")
            explanation["pros"].append("Standard service (likely required)")
            explanation["cons"].append("Requires proper hardening")
            explanation["recommendations"].append("Use updated version with security patches")
            explanation["recommendations"].append("Apply principle of least privilege")
        
        else:  # LOW
            explanation["reasoning"].append(f"Port {port} ({service}) has low inherent risk")
            explanation["pros"].append("Standard system service")
            explanation["pros"].append("Low severity vulnerabilities typically associated")
            explanation["recommendations"].append("Keep service updated")
            explanation["recommendations"].append("Monitor for unusual activity")
        
        # CVSS-based reasoning
        if cvss >= 9:
            explanation["reasoning"].append(f"CVSS score {cvss} indicates critical vulnerability impact")
        elif cvss >= 7:
            explanation["reasoning"].append(f"CVSS score {cvss} indicates high vulnerability impact")
        elif cvss >= 4:
            explanation["reasoning"].append(f"CVSS score {cvss} indicates moderate vulnerability")
        
        return explanation
    
    @staticmethod
    def explain_attack_scenarios(ports: List[Dict[str, Any]], os_name: str) -> Dict[str, Any]:
        """
        Generate realistic attack scenarios based on open ports and OS
        """
        scenarios = {
            "os": os_name,
            "attack_scenarios": [],
            "likelihood": "MEDIUM"
        }
        
        port_numbers = [p["port"] for p in ports]
        
        # Scenario 1: Brute force attack
        if 22 in port_numbers or 3389 in port_numbers or 3306 in port_numbers:
            scenarios["attack_scenarios"].append({
                "name": "Brute Force Attack",
                "description": "Attacker performs dictionary/brute force attack on exposed authentication services",
                "target_ports": [p for p in port_numbers if p in [22, 3389, 3306, 5432]],
                "likelihood": "HIGH",
                "impact": "Account compromise, lateral movement"
            })
        
        # Scenario 2: Service exploitation
        vulnerable_ports = [p for p in port_numbers if p in [23, 21, 445, 139, 2049]]
        if vulnerable_ports:
            scenarios["attack_scenarios"].append({
                "name": "Service Exploitation",
                "description": "Attacker exploits known vulnerabilities in exposed services",
                "target_ports": vulnerable_ports,
                "likelihood": "HIGH",
                "impact": "Remote code execution, privilege escalation"
            })
        
        # Scenario 3: Information disclosure
        if 53 in port_numbers or 389 in port_numbers:
            scenarios["attack_scenarios"].append({
                "name": "Information Disclosure",
                "description": "Attacker queries DNS/LDAP to discover internal system information",
                "target_ports": [p for p in port_numbers if p in [53, 389]],
                "likelihood": "MEDIUM",
                "impact": "System enumeration, service discovery"
            })
        
        # Scenario 4: Web application attack (if HTTP/HTTPS)
        if 80 in port_numbers or 443 in port_numbers or 8080 in port_numbers:
            scenarios["attack_scenarios"].append({
                "name": "Web Application Attack",
                "description": "Attacker targets web application via HTTP/HTTPS ports",
                "target_ports": [p for p in port_numbers if p in [80, 443, 8080, 8888, 3000]],
                "likelihood": "MEDIUM",
                "impact": "SQL injection, XSS, authentication bypass"
            })
        
        # Scenario 5: Network scanning and pivoting
        if len(ports) >= 5:
            scenarios["attack_scenarios"].append({
                "name": "Network Scanning & Lateral Movement",
                "description": "Attacker uses compromised host as pivot point to scan internal network",
                "target_ports": port_numbers[:3],
                "likelihood": "MEDIUM",
                "impact": "Internal network compromise, multi-host infection"
            })
        
        # Determine overall likelihood
        critical_ports = [p for p in port_numbers if p in [23, 445, 139, 2049]]
        if len(critical_ports) > 0:
            scenarios["likelihood"] = "CRITICAL"
        elif len(ports) >= 5:
            scenarios["likelihood"] = "HIGH"
        
        return scenarios
    
    @staticmethod
    def generate_port_explanation(port: int, service: str, version: str = None) -> str:
        """Generate a concise explanation of what a port does"""
        explanations = {
            22: "SSH allows encrypted remote administration. Usually required but should be restricted by IP.",
            21: "FTP transfers files unencrypted. Outdated service—use SFTP/SCP instead.",
            23: "Telnet provides unencrypted remote access. MUST be disabled; use SSH instead.",
            25: "SMTP sends emails. Core mail service but should only accept from trusted sources.",
            53: "DNS resolves domain names. Essential for network, but zone transfers should be restricted.",
            80: "HTTP serves web content unencrypted. Use HTTPS (443) for sensitive data.",
            110: "POP3 retrieves emails. Transmits authentication unencrypted—deprecated for POP3S.",
            143: "IMAP accesses emails. Uses unencrypted auth by default—use IMAPS (993) instead.",
            389: "LDAP provides directory services. Anonymous binds should be disabled.",
            443: "HTTPS serves encrypted web content. Security depends on certificate validity.",
            445: "SMB shares files/printers on Windows networks. High-value target for ransomware/worms.",
            3306: "MySQL database server. Should NEVER be internet-exposed; restrict to internal only.",
            3389: "RDP (Windows remote desktop). High-value target—restrict by IP and use strong auth.",
            5432: "PostgreSQL database. Should be internal-only; restrict access strictly.",
            5900: "VNC remote access. Weak authentication—disable or use SSH tunneling.",
            1433: "MSSQL database. High-value target—should be internal only, never internet-facing.",
            2049: "NFS shared filesystem. No authentication by default—serious security risk if exposed.",
            123: "NTP synchronizes time. Can amplify DDoS attacks if misconfigured.",
        }
        
        if version:
            return f"{explanations.get(port, f'Service on port {port} ({service})')} Running {version}."
        return explanations.get(port, f"Service on port {port} ({service}). High-value network resource.")
