import scapy.all as scapy
import nmap
import concurrent.futures

def scan_network(ip_range):
    """
    Performs an ARP scan to identify active devices on the network.
    """
    packet = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined_packet = broadcast / packet
    result = scapy.srp(combined_packet, timeout=3, verbose=0)[0]
    
    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

def detect_os(ip):
    """
    Detects the operating system of a given IP.
    """
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-O')
    if 'osmatch' in scanner[ip] and scanner[ip]['osmatch']:
        return scanner[ip]['osmatch'][0]['name']
    return "OS could not be determined."

def scan_ports(ip):
    """
    Scans open ports for a given IP using nmap.
    """
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-p 1-65535')
    ports = {}
    if 'tcp' in scanner[ip]:
        for port, port_data in scanner[ip]['tcp'].items():
            ports[port] = port_data['name']
    return ports

def scan_vulnerabilities(ip, ports):
    """
    Scans for vulnerabilities on the open ports using nmap's --script vuln option.
    """
    scanner = nmap.PortScanner()
    vulnerabilities = []
    for port in ports:
        scanner.scan(ip, arguments=f'--script vuln -p {port}')
        if 'hostscript' in scanner[ip]:
            for vuln in scanner[ip]['hostscript']:
                vulnerabilities.append(vuln)
    return vulnerabilities

def scan_device_for_ports_and_vulnerabilities(device):
    """
    Scans a device for open ports and vulnerabilities on those ports.
    """
    ip = device['ip']
    print(f"\nScanning device {ip}...")

    # Scan for open ports
    ports = scan_ports(ip)
    print(f"  Open Ports:")
    for port, service in ports.items():
        print(f"    Port {port}: {service}")
    
    # Scan vulnerabilities for the open ports
    vulnerabilities = scan_vulnerabilities(ip, ports)
    print(f"  Vulnerabilities:")
    if vulnerabilities:
        for vuln in vulnerabilities:
            print(f"    {vuln['id']}: {vuln['output']}")
    else:
        print("    No vulnerabilities found.")

    print("-" * 50)

# Main Functionality
if __name__ == "__main__":
    target_network = input("Enter the IP range (e.g., 192.168.1.0/24): ")
    devices = scan_network(target_network)

    print("\nDiscovered Devices:")
    # Use ThreadPoolExecutor to scan the devices for OS
    with concurrent.futures.ThreadPoolExecutor() as executor:
        os_results = list(executor.map(lambda device: (device, detect_os(device['ip'])), devices))
    
    # Display IP and OS for each device
    for idx, (device, os) in enumerate(os_results):
        device['os'] = os
        print(f"{idx + 1}. IP: {device['ip']}, OS: {os}")

    # Ask user to select a device
    selected_device_index = int(input("\nEnter the number of the device you want to scan further: ")) - 1
    selected_device = devices[selected_device_index]

    # Now, scan the selected device for ports and vulnerabilities
    scan_device_for_ports_and_vulnerabilities(selected_device)
