"""
Service mapper — standardize service names with fallback mappings
Maps port numbers to standard service names and default risk profiles
"""

from typing import Dict, Tuple

SERVICE_MAPPING = {
    # FTP/SSH/Telnet
    21: ("FTP", "File Transfer Protocol"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Unencrypted Remote Login"),
    
    # Email
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    110: ("POP3", "Post Office Protocol v3"),
    143: ("IMAP", "Internet Message Access Protocol"),
    
    # DNS/DHCP
    53: ("DNS", "Domain Name System"),
    67: ("DHCP", "Dynamic Host Configuration"),
    68: ("DHCP", "Dynamic Host Configuration"),
    
    # HTTP/HTTPS
    80: ("HTTP", "Hypertext Transfer Protocol"),
    443: ("HTTPS", "HTTP Secure"),
    3000: ("HTTP-Alt", "HTTP Alternate"),
    3001: ("HTTP-Alt", "HTTP Alternate"),
    5000: ("HTTP-Alt", "HTTP Alternate"),
    8080: ("HTTP-Alt", "HTTP Alternate"),
    8888: ("HTTP-Alt", "HTTP Alternate"),
    9000: ("HTTP-Alt", "HTTP Alternate"),
    
    # Database
    3306: ("MySQL", "MySQL Database Server"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1521: ("Oracle", "Oracle Database"),
    
    # Remote Desktop
    3389: ("RDP", "Remote Desktop Protocol"),
    5900: ("VNC", "Virtual Network Computing"),
    5901: ("VNC", "Virtual Network Computing"),
    
    # LDAP
    389: ("LDAP", "Lightweight Directory Access Protocol"),
    636: ("LDAPS", "LDAP Secure"),
    
    # Kerberos
    88: ("Kerberos", "Kerberos Authentication"),
    
    # NetBIOS/SMB
    137: ("NetBIOS", "NetBIOS Name Service"),
    138: ("NetBIOS", "NetBIOS Datagram Service"),
    139: ("SMB", "NetBIOS Session Service"),
    445: ("SMB", "Server Message Block"),
    
    # NFS
    2049: ("NFS", "Network File System"),
    
    # IRC
    6667: ("IRC", "Internet Relay Chat"),
    
    # NTP
    123: ("NTP", "Network Time Protocol"),
    
    # SNMP
    161: ("SNMP", "Simple Network Management Protocol"),
    162: ("SNMP", "SNMP Trap"),
    
    # Other common
    135: ("RPC", "Remote Procedure Call"),
    139: ("SMB", "Network File Sharing"),
    512: ("Rexec", "Remote Execution"),
    513: ("Rlogin", "Remote Login"),
    514: ("Syslog", "System Logging"),
}

RISK_LEVELS_BY_PORT = {
    # CRITICAL RISK
    23: "CRITICAL",   # Telnet (unencrypted)
    69: "CRITICAL",   # TFTP
    
    # HIGH RISK
    21: "HIGH",       # FTP
    22: "HIGH",       # SSH (high value target)
    3306: "HIGH",     # MySQL
    3389: "HIGH",     # RDP
    1433: "HIGH",     # MSSQL
    1521: "HIGH",     # Oracle
    445: "HIGH",      # SMB
    139: "HIGH",      # NetBIOS
    2049: "HIGH",     # NFS
    
    # MEDIUM RISK
    25: "MEDIUM",     # SMTP
    53: "MEDIUM",     # DNS
    80: "MEDIUM",     # HTTP
    110: "MEDIUM",    # POP3
    143: "MEDIUM",    # IMAP
    389: "MEDIUM",    # LDAP
    443: "MEDIUM",    # HTTPS
    587: "MEDIUM",    # SMTP TLS
    3000: "MEDIUM",   # HTTP Alt
    3001: "MEDIUM",   # HTTP Alt
    5000: "MEDIUM",   # HTTP Alt
    5432: "MEDIUM",   # PostgreSQL
    5900: "MEDIUM",   # VNC
    8080: "MEDIUM",   # HTTP Alt
    8888: "MEDIUM",   # HTTP Alt
    9000: "MEDIUM",   # HTTP Alt
    
    # LOW RISK
    88: "LOW",        # Kerberos
    123: "LOW",       # NTP
    137: "LOW",       # NetBIOS
    138: "LOW",       # NetBIOS
    161: "LOW",       # SNMP
    162: "LOW",       # SNMP
    512: "LOW",       # Rexec
    513: "LOW",       # Rlogin
    514: "LOW",       # Syslog
    636: "LOW",       # LDAPS
    6667: "LOW",      # IRC
}

def map_service_name(port: int, nmap_service: str = None) -> Tuple[str, str]:
    """
    Map port to standard service name.
    Falls back to port mapping if nmap service is unknown.
    
    Returns: (service_name, description)
    """
    if nmap_service and nmap_service.lower() != "unknown":
        # Use Nmap detected service if available
        if port in SERVICE_MAPPING:
            return SERVICE_MAPPING[port]
        return (nmap_service, "")
    
    # Fallback to port-based mapping
    if port in SERVICE_MAPPING:
        return SERVICE_MAPPING[port]
    
    return ("Unknown", "")

def get_risk_level_for_port(port: int) -> str:
    """Get default risk level for a port"""
    return RISK_LEVELS_BY_PORT.get(port, "LOW")

def get_attack_vectors_for_port(port: int, service: str, version: str = None) -> Dict[str, str]:
    """
    Get potential attack vectors for a port/service combination
    """
    vectors = {
        22: "SSH brute force, auth bypass exploits, version-specific vulnerabilities",
        21: "FTP auth bypass, unencrypted credentials, directory traversal",
        23: "Telnet sniffing (unencrypted), man-in-the-middle attacks",
        25: "Email spoofing, SMTP relay abuse, version enumeration",
        53: "DNS spoofing, DNS amplification (DDoS), zone transfers",
        80: "HTTP vulnerabilities, man-in-the-middle, SQL injection via web",
        110: "POP3 auth sniffing, weak encryption",
        143: "IMAP auth sniffing, weak encryption",
        389: "LDAP injection, anonymous bind, credential enumeration",
        443: "HTTPS weaknesses, certificate pinning bypass, cipher downgrades",
        445: "SMB exploits (EternalBlue, Wannacry), RCE, privilege escalation",
        3306: "MySQL authentication bypass, SQL injection, data theft",
        3389: "RDP brute force, credential theft, privilege escalation",
        5432: "PostgreSQL injection, weak auth, data exfiltration",
        5900: "VNC auth bypass, screen capture, remote control",
        1433: "MSSQL injection, xp_cmdshell RCE, authentication bypass",
        2049: "NFS mounting, directory traversal, privilege escalation",
    }
    return vectors.get(port, "Standard port exploitation techniques")
