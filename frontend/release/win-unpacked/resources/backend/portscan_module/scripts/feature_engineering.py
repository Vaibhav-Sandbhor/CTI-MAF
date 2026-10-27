import xml.etree.ElementTree as ET
import os
import math
from collections import Counter
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "data"))
from port_knowledge import PORT_KNOWLEDGE

# -------------------------------
# CONFIGURATION
# -------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
XML_FILE = os.path.join(PROJECT_ROOT, "nmap_scans", "scan1.xml")

# Common ports (normal services)
COMMON_PORTS = {21, 22, 25, 53, 80, 110, 443}

# Risk level to numeric weight mapping
RISK_LEVEL_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1
}

# -------------------------------
# STEP 1: PARSE NMAP XML
# -------------------------------
def parse_nmap(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    hosts_data = []

    for host in root.findall("host"):
        host_info = {}

        # IP address
        address = host.find("address")
        host_info["ip"] = address.attrib.get("addr") if address is not None else "Unknown"

        # OS detection
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            host_info["os"] = osmatch.attrib.get("name") if osmatch is not None else "Unknown"
        else:
            host_info["os"] = "Unknown"

        open_ports = []
        services = []
        port_services = {}

        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state = port.find("state")
                if state is not None and state.attrib.get("state") == "open":
                    port_id = int(port.attrib.get("portid"))
                    open_ports.append(port_id)

                    service = port.find("service")
                    if service is not None:
                        service_name = service.attrib.get("name", "unknown")
                        services.append(service_name)
                        port_services[port_id] = service_name
                    else:
                        port_services[port_id] = "unknown"

        host_info["open_ports"] = open_ports
        host_info["services"] = list(set(services))
        host_info["port_services"] = port_services

        hosts_data.append(host_info)

    return hosts_data

# -------------------------------
# STEP 2A: HELPER FUNCTIONS FOR ADVANCED FEATURE ENGINEERING
# -------------------------------
def calculate_port_severity_score(open_ports):
    """
    Calculate sum of risk weights for all open ports.
    
    Uses PORT_KNOWLEDGE to map each port to risk_level,
    then converts risk_level to numeric weight:
        Critical = 4, High = 3, Medium = 2, Low = 1
    
    If port not in database, default weight = 1
    """
    total_severity = 0
    
    for port in open_ports:
        port_info = PORT_KNOWLEDGE.get(port)
        if port_info:
            risk_level = port_info.get("risk_level", "Low")
            weight = RISK_LEVEL_WEIGHTS.get(risk_level, 1)
        else:
            weight = 1  # Unknown port gets weight 1
        
        total_severity += weight
    
    return total_severity


def calculate_high_risk_port_count(open_ports):
    """Count open ports labeled as High or Critical risk."""
    count = 0
    
    for port in open_ports:
        port_info = PORT_KNOWLEDGE.get(port)
        if port_info:
            risk_level = port_info.get("risk_level", "Low")
            if risk_level in ["High", "Critical"]:
                count += 1
    
    return count


def calculate_service_entropy(services):
    """
    Calculate Shannon entropy of service distribution.
    
    Higher entropy = more diverse services (potentially more attack surface)
    Lower entropy = concentrated services (less attack surface, but deeper)
    
    Formula: entropy = -sum(p * log2(p)) where p = frequency of service
    """
    if not services or len(services) <= 1:
        return 0.0
    
    # Count service frequencies
    service_counts = Counter(services)
    total = len(services)
    
    entropy = 0.0
    for count in service_counts.values():
        probability = count / total
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return round(entropy, 4)


def calculate_cvss_variance(services):
    """
    Calculate variance of CVSS scores across services.
    
    Uses PORT_KNOWLEDGE to get CVSS values.
    If service not found or only one service, variance = 0
    """
    # Get CVSS scores from PORT_KNOWLEDGE
    cvss_scores = []
    
    for service in services:
        # Find port number by matching service name in PORT_KNOWLEDGE
        for port, info in PORT_KNOWLEDGE.items():
            if info.get("service_name", "").lower() == service.lower():
                # For simplicity, map risk_level to CVSS proxy
                risk_level = info.get("risk_level", "Low")
                cvss_proxy = {
                    "Critical": 8.5,
                    "High": 6.5,
                    "Medium": 4.5,
                    "Low": 2.5
                }.get(risk_level, 3.0)
                cvss_scores.append(cvss_proxy)
                break
    
    if len(cvss_scores) <= 1:
        return 0.0
    
    # Calculate variance
    mean = sum(cvss_scores) / len(cvss_scores)
    variance = sum((x - mean) ** 2 for x in cvss_scores) / len(cvss_scores)
    
    return round(variance, 4)


def calculate_features(host):
    """
    Calculate all engineering features for a host.
    
    Original Features (5):
    - open_ports_count: Number of open ports
    - service_count: Number of unique services
    - avg_cvss: Average CVSS score of services
    - uncommon_ports: Boolean flag for non-standard ports
    - os_flag: Windows (1) or Other (0)
    
    Advanced Security Features (4):
    - port_severity_score: Sum of risk weights (High=3, Critical=4, etc)
    - high_risk_port_count: Count of High/Critical ports
    - service_entropy: Shannon entropy of service distribution
    - cvss_variance: Variance of CVSS scores
    """
    open_ports = host["open_ports"]
    services = host["services"]
    os_name = host["os"].lower()

    open_ports_count = len(open_ports)
    service_count = len(services)

    # Calculate average CVSS from PORT_KNOWLEDGE
    cvss_scores = []
    for port in open_ports:
        port_info = PORT_KNOWLEDGE.get(port)
        if port_info:
            risk_level = port_info.get("risk_level", "Low")
            # Map risk level to CVSS estimate
            cvss_estimate = {
                "Critical": 8.5,
                "High": 6.5,
                "Medium": 4.5,
                "Low": 2.5
            }.get(risk_level, 3.0)
            cvss_scores.append(cvss_estimate)
        else:
            cvss_scores.append(3.0)  # Unknown port default
    
    avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 2) if cvss_scores else 0

    # OS flag (Windows = 1, Others = 0)
    os_flag = 1 if "windows" in os_name.lower() or os_name == "unknown" else 0

    # Uncommon port detection
    uncommon_ports = 0
    for port in open_ports:
        if port not in COMMON_PORTS:
            uncommon_ports = 1
            break

    # ═══════════════════════════════════════════════════════════════
    # ADVANCED SECURITY FEATURES
    # ═══════════════════════════════════════════════════════════════
    
    # 1. Port Severity Score: Sum of risk weights
    port_severity_score = calculate_port_severity_score(open_ports)
    
    # 2. High Risk Port Count: Count of High/Critical ports
    high_risk_port_count = calculate_high_risk_port_count(open_ports)
    
    # 3. Service Entropy: Diversity of services
    service_entropy = calculate_service_entropy(services)
    
    # 4. CVSS Variance: Spread of CVSS scores
    cvss_variance = calculate_cvss_variance(services)

    return {
        # Original features
        "open_ports_count": open_ports_count,
        "service_count": service_count,
        "avg_cvss": avg_cvss,
        "uncommon_ports": uncommon_ports,
        "os_flag": os_flag,
        # Advanced security features
        "port_severity_score": port_severity_score,
        "high_risk_port_count": high_risk_port_count,
        "service_entropy": service_entropy,
        "cvss_variance": cvss_variance
    }

# -------------------------------
# MAIN
# -------------------------------
if __name__ == "__main__":
    hosts = parse_nmap(XML_FILE)

    print("\n=== FEATURE ENGINEERING OUTPUT ===\n")
    for host in hosts:
        features = calculate_features(host)
        print(features)
