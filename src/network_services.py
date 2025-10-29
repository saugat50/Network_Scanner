import nmap
import netifaces as ni
from scapy.all import sniff, IP, TCP, Raw, send
import re

def get_local_network_range():
    gws = ni.gateways()
    default_interface = gws['default'][ni.AF_INET][1]
    ip_info = ni.ifaddresses(default_interface)[ni.AF_INET][0]
    ip_address = ip_info['addr']
    netmask = ip_info['netmask']
    ip_parts = ip_address.split('.')
    mask_parts = netmask.split('.')
    network_parts = [str(int(ip_parts[i]) & int(mask_parts[i])) for i in range(4)]
    network_range = '.'.join(network_parts) + '/24'
    return network_range

def discover_hosts(network_range):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_range, arguments='-sn')
    except Exception as e:
        print(f"Error during scanning: {e}")
        return []
    active_hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            active_hosts.append({
                'IP Address': host,
                'Hostname': nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else ''
            })
    return active_hosts

def scan_ports(ip_address):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip_address, arguments='-sS', timeout=10)
        open_ports = []
        for proto in nm[ip_address].all_protocols():
            lport = nm[ip_address][proto].keys()
            for port in sorted(lport):
                if nm[ip_address][proto][port]['state'] == 'open':
                    open_ports.append((port, nm[ip_address][proto][port]['name']))
        return open_ports
    except Exception as e:
        print(f"Error scanning ports on {ip_address}: {e}")
        return []

def service_enumeration(network_range):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_range, arguments='-sV -A')
    except Exception as e:
        print(f"Error during service enumeration: {e}")
        return []
    all_services = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            host_services = []
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    service_info = {
                        'port': port,
                        'service': nm[host][proto][port]['name'],
                        'product': nm[host][proto][port].get('product', ''),
                        'version': nm[host][proto][port].get('version', '')
                    }
                    host_services.append(service_info)
            if host_services:
                all_services.append({'host': host, 'services': host_services})
    return all_services

def vulnerability_scan(network_range):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_range, arguments='-sV')
    except Exception as e:
        print(f"Error during vulnerability scanning: {e}")
        return []
    results = []
    for host in nm.all_hosts():
        host_info = {'IP': host, 'State': nm[host].state(), 'Services': []}
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                service_info = {
                    'Port': port,
                    'Service': nm[host][proto][port]['name'],
                    'Version': nm[host][proto][port].get('version', 'Unknown')
                }
                host_info['Services'].append(service_info)
        results.append(host_info)
    return results

def packet_callback(packet):
    try:
        if IP in packet and TCP in packet and packet.haslayer(Raw):
            if packet[TCP].dport == 80 and b"GET" in packet[Raw].load:
                url_match = re.search(b"(?i)\\bHost:\\s*(.*?)\\r\\n", packet[Raw].load)
                if url_match:
                    print(f"HTTP GET request to: {url_match.group(1).decode()}")
    except Exception as e:
        print(f"Error processing packet: {e}")

def start_sniffing(target_ip):
    print(f"Starting to sniff HTTP traffic from IP: {target_ip}")
    sniff(filter=f"ip host {target_ip} and tcp port 80", prn=packet_callback, store=False)

def main():
    network = get_local_network_range()
    print("Discovering hosts in the local network...")
    hosts = discover_hosts(network)
    if hosts:
        print("Connected devices:")
        for host in hosts:
            print(f"IP Address: {host['IP Address']}, Hostname: {host['Hostname']}")
    else:
        print("No devices found in the local network.")

    while True:
        print("\n1. Search for open ports")
        print("2. Enumerate services on a network")
        print("3. Perform a vulnerability scan")
        print("4. Sniff HTTP GET requests")
        print("5. Exit")
        choice = input("Enter your choice (1, 2, 3, 4, or 5): ")

        if choice == '1':
            ip_to_scan = input("Enter the IP address to scan for open ports: ")
            open_ports = scan_ports(ip_to_scan)
            if open_ports:
                print(f"Open ports on {ip_to_scan}: {open_ports}")
            else:
                print("No open ports found.")
        elif choice == '2':
            network_range = input("Enter the network range to enumerate services (e.g., 192.168.1.0/24): ")
            services = service_enumeration(network_range)
            for host_info in services:
                print(f'Host: {host_info["host"]}')
                for service in host_info['services']:
                    print(f'  Port: {service["port"]}, Service: {service["service"]}, Product: {service["product"]}, Version: {service["version"]}')
        elif choice == '3':
            network_range = input("Enter the network range for vulnerability scanning (e.g., 192.168.1.0/24): ")
            vulnerabilities = vulnerability_scan(network_range)
            for result in vulnerabilities:
                print(f"IP Address: {result['IP']}, State: {result['State']}")
                for service in result['Services']:
                    print(f"  Port: {service['Port']}, Service: {service['Service']}, Version: {service['Version']}")
        elif choice == '4':
            target_ip = input("Enter the IP address to monitor for HTTP GET requests: ")
            start_sniffing(target_ip)
        elif choice == '5':
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

if __name__ == "__main__":
    main()
