import nmap
import netifaces as ni

def get_local_network_range():
    try:
        gws = ni.gateways()
        default_interface = gws['default'][ni.AF_INET][1]
        ip_info = ni.ifaddresses(default_interface)[ni.AF_INET][0]
        ip_address = ip_info['addr']
        netmask = ip_info['netmask']
        ip_parts = ip_address.split('.')
        mask_parts = netmask.split('.')
        network_parts = [str(int(ip_parts[i]) & int(mask_parts[i])) for i in range(4)]
        return '.'.join(network_parts) + '/24'
    except Exception as e:
        return f"Error: {e}"

def discover_hosts(network_range):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_range, arguments='-sn')
        active_hosts = [
            {
                'IP Address': host,
                'Hostname': nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else ''
            }
            for host in nm.all_hosts()
            if nm[host].state() == 'up'
        ]
        return active_hosts
    except Exception as e:
        return f"Error: {e}"

def scan_ports(ip_address):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip_address, arguments='-sS')
        open_ports = [
            (port, nm[ip_address][proto][port]['name'])
            for proto in nm[ip_address].all_protocols()
            for port in sorted(nm[ip_address][proto].keys())
            if nm[ip_address][proto][port]['state'] == 'open'
        ]
        return open_ports
    except Exception as e:
        return f"Error: {e}"

def service_enumeration(network_range):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_range, arguments='-sV -A')
        return [
            {
                'host': host,
                'services': [
                    {
                        'port': port,
                        'service': nm[host][proto][port]['name'],
                        'product': nm[host][proto][port].get('product', ''),
                        'version': nm[host][proto][port].get('version', '')
                    }
                    for proto in nm[host].all_protocols()
                    for port in sorted(nm[host][proto].keys())
                ]
            }
            for host in nm.all_hosts() if nm[host].state() == 'up'
        ]
    except Exception as e:
        return f"Error: {e}"

def vulnerability_scan(network_range):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_range, arguments='-sV')
        return [
            {
                'IP': host,
                'State': nm[host].state(),
                'Services': [
                    {
                        'Port': port,
                        'Service': nm[host][proto][port]['name'],
                        'Version': nm[host][proto][port].get('version', 'Unknown')
                    }
                    for proto in nm[host].all_protocols()
                    for port in sorted(nm[host][proto].keys())
                ]
            }
            for host in nm.all_hosts()
        ]
    except Exception as e:
        return f"Error: {e}"
