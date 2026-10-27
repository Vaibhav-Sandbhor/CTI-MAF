import xml.etree.ElementTree as ET

# Path to Nmap XML file
XML_FILE = "nmap_scans/scan1.xml"

def parse_nmap(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    hosts_data = []

    for host in root.findall("host"):
        host_info = {}

        # IP Address
        address = host.find("address")
        if address is not None:
            host_info["ip"] = address.attrib.get("addr")

        # OS detection
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                host_info["os"] = osmatch.attrib.get("name")
            else:
                host_info["os"] = "Unknown"
        else:
            host_info["os"] = "Unknown"

        open_ports = []
        services = []

        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state = port.find("state")
                if state is not None and state.attrib.get("state") == "open":
                    port_id = port.attrib.get("portid")
                    service = port.find("service")

                    open_ports.append(port_id)

                    if service is not None:
                        services.append(service.attrib.get("name"))

        host_info["open_ports_count"] = len(open_ports)
        host_info["services"] = list(set(services))

        hosts_data.append(host_info)

    return hosts_data


if __name__ == "__main__":
    data = parse_nmap(XML_FILE)
    for host in data:
        print(host)
