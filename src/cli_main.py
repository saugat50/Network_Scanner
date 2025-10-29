# Simple CLI wrapper for Network-Scanner
# Usage: python3 src/cli_main.py --host 192.168.1.1 --ports 22,80,443
import argparse
import socket
import sys

def simple_port_scan(host, ports, timeout=1.0):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((host, port))
                if res == 0:
                    open_ports.append(port)
        except Exception as e:
            pass
    return open_ports

def try_use_scanner_module(host, ports):
    # attempt to import a helper from scanner.py (best-effort)
    try:
        import importlib
        scanner = importlib.import_module('scanner')
        # common helper names: scan_host, scan_ports, scan_network
        for fn in ('scan_host','scan_ports','scan_network','run_scan'):
            if hasattr(scanner, fn):
                func = getattr(scanner, fn)
                try:
                    return func(host, ports)
                except Exception:
                    # ignore and fallback
                    pass
    except Exception:
        pass
    return None

def parse_ports(ports_str):
    parts = ports_str.split(',') if ports_str else []
    ports = []
    for p in parts:
        if '-' in p:
            a,b = p.split('-',1)
            ports.extend(range(int(a), int(b)+1))
        else:
            if p.strip():
                ports.append(int(p.strip()))
    return sorted(set(ports))

def main():
    parser = argparse.ArgumentParser(description='CLI for Network-Scanner (minimal)')
    parser.add_argument('--host', required=True, help='Target host IP or hostname')
    parser.add_argument('--ports', default='22,80,443', help='Comma-separated ports or ranges (e.g. 1-1024,80,443)')
    parser.add_argument('--timeout', type=float, default=1.0, help='Socket timeout in seconds')
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    # try scanner module
    res = try_use_scanner_module(args.host, ports)
    if res:
        print('Result from scanner module:', res)
        sys.exit(0)

    print(f'Starting simple port scan on {args.host} for ports: {ports}')
    open_ports = simple_port_scan(args.host, ports, timeout=args.timeout)
    if open_ports:
        print('Open ports:', open_ports)
    else:
        print('No open ports found.')

if __name__ == '__main__':
    main()
