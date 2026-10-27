"""
Nmap scanner module — handles advanced port scanning and OS detection
Extracts: OS name, OS accuracy, device type, service version, product info
"""

import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Any

class NmapScanner:
    def __init__(self, nmap_path: str = "nmap"):
        self.nmap_path = nmap_path
    
    def scan_target(self, target: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Run advanced Nmap scan: -sS -sV -O -A
        Returns: parsed XML data with OS, services, versions
        """
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name
        
        try:
            cmd = [
                self.nmap_path,
                "-sS",          # SYN scan
                "-sV",          # Service version detection
                "-O",           # OS detection
                "-A",           # Aggressive scan (OS, version, script, traceroute)
                "-T5",          # Insane timing
                "--top-ports", "1000",
                "--min-rate", "5000",
                "-oX", xml_path,
                target
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if __import__('os').name == 'nt' else 0
            )
            
            if result.returncode != 0:
                return {
                    "error": f"Nmap error: {result.stderr.strip() or 'non-zero exit'}",
                    "data": None
                }
            
            # Parse XML output
            data = self._parse_nmap_xml(xml_path)
            return {"error": None, "data": data}
        
        except subprocess.TimeoutExpired:
            return {"error": "Nmap scan timed out", "data": None}
        except Exception as e:
            return {"error": str(e), "data": None}
        finally:
            import os
            try:
                os.remove(xml_path)
            except:
                pass
    
    def _parse_nmap_xml(self, xml_path: str) -> Dict[str, Any]:
        """Parse Nmap XML output, extract OS, services, versions"""
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        hosts_data = []
        
        for host in root.findall("host"):
            host_info = {
                "ip": host.find("address").get("addr") if host.find("address") is not None else "unknown",
                "os": self._extract_os_info(host),
                "ports": self._extract_ports_with_versions(host),
                "cpe": self._extract_cpe(host),
            }
            hosts_data.append(host_info)
        
        return hosts_data
    
    def _extract_os_info(self, host: ET.Element) -> Dict[str, Any]:
        """Extract OS name, accuracy, device type"""
        os_elem = host.find("os")
        if os_elem is None:
            return {
                "name": "Unknown",
                "accuracy": 0,
                "device_type": "Unknown",
                "cpe": None
            }
        
        osmatch = os_elem.find("osmatch")
        if osmatch is None:
            return {
                "name": "Unknown",
                "accuracy": 0,
                "device_type": "Unknown",
                "cpe": None
            }
        
        os_name = osmatch.get("name", "Unknown")
        os_accuracy = int(osmatch.get("accuracy", 0))
        
        # Extract device type from osclass
        device_type = "Unknown"
        osclass = osmatch.find("osclass")
        if osclass is not None:
            device_type = osclass.get("type", "Unknown")
        
        return {
            "name": os_name,
            "accuracy": os_accuracy,
            "device_type": device_type,
            "cpe": osmatch.find("cpe").text if osmatch.find("cpe") is not None else None
        }
    
    def _extract_ports_with_versions(self, host: ET.Element) -> List[Dict[str, Any]]:
        """Extract ports with service names and versions"""
        ports = []
        ports_elem = host.find("ports")
        
        if ports_elem is None:
            return ports
        
        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue
            
            port_num = int(port_elem.get("portid", 0))
            service_elem = port_elem.find("service")
            
            port_info = {
                "port": port_num,
                "service_name": service_elem.get("name", "Unknown") if service_elem is not None else "Unknown",
                "product": service_elem.get("product", None) if service_elem is not None else None,
                "version": service_elem.get("version", None) if service_elem is not None else None,
                "extrainfo": service_elem.get("extrainfo", None) if service_elem is not None else None,
                "ostype": service_elem.get("ostype", None) if service_elem is not None else None,
            }
            ports.append(port_info)
        
        return sorted(ports, key=lambda x: x["port"])
    
    def _extract_cpe(self, host: ET.Element) -> List[str]:
        """Extract CPE information for vulnerabilities"""
        cpes = []
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                cpe_elem = osmatch.find("cpe")
                if cpe_elem is not None:
                    cpes.append(cpe_elem.text)
        
        return cpes
