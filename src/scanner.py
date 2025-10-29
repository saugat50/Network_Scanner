# src/scanner.py
"""
Network Scanner - Kivy GUI frontend with safe fallbacks.

Features:
- Tries to use optional `final.py` functions if present:
  discover_hosts(network_range), scan_ports(host), service_enumeration(network_range),
  vulnerability_scan(network_range)
- If `final.py` is absent, uses safe fallback implementations that avoid raw sockets.
- Optional packet sniffing via scapy (requires scapy + admin privileges).
- Scrollable, styled Kivy UI suitable for small screens.
"""

import threading
import socket
import ipaddress
import json
import time

# Kivy imports
from kivy.config import Config
# set window size before importing Window
Config.set('graphics', 'width', '520')
Config.set('graphics', 'height', '650')
Config.set('graphics', 'resizable', '1')

from kivy.core.window import Window
from kivy.app import App
from kivy.clock import Clock
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup

# set clean background color (dark)
Window.clearcolor = (0.08, 0.08, 0.08, 1)

# Try to import optional final.py (project-specific scanning logic)
try:
    import final  # if your project includes final.py, its functions will be used
except Exception:
    final = None

# Try to import scapy for sniffing (optional)
try:
    from scapy.all import sniff, TCP, IP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# ---------------- Fallback scanning implementations -----------------------
def fallback_discover_hosts(network_range, timeout=0.5, ports=(80, 443)):
    """
    Discover hosts using TCP connect on common ports (no raw ICMP required).
    Returns list of dicts: [{'ip': 'x.x.x.x', 'up': True/False}, ...]
    """
    try:
        net = ipaddress.ip_network(network_range, strict=False)
    except Exception as e:
        return {"error": f"Invalid network range: {e}"}

    results = []
    for ip in net.hosts():
        ip_str = str(ip)
        is_up = False
        for p in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                code = s.connect_ex((ip_str, p))
                s.close()
                if code == 0:
                    is_up = True
                    break
            except Exception:
                pass
        results.append({"ip": ip_str, "up": is_up})
    return results


def fallback_scan_ports(host, ports_list=None, timeout=0.5):
    """
    Simple TCP connect port scan for the provided host.
    Returns list of open ports.
    """
    if ports_list is None:
        ports_list = [22, 21, 23, 80, 443, 3389, 3306, 8080]
    open_ports = []
    for port in ports_list:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((host, int(port))) == 0:
                open_ports.append(int(port))
            s.close()
        except Exception:
            pass
    return open_ports


def fallback_service_enumeration(network_range):
    """
    For each discovered host, run a small fallback_scan_ports and return summary.
    """
    discovered = fallback_discover_hosts(network_range)
    if isinstance(discovered, dict) and discovered.get("error"):
        return discovered
    summary = []
    for d in discovered:
        if d.get("up"):
            ip = d["ip"]
            ports = fallback_scan_ports(ip, ports_list=[22, 80, 443, 8080, 3306])
            summary.append({"ip": ip, "open_ports": ports})
    return summary


def fallback_vulnerability_scan(network_range):
    return {"note": "Detailed vulnerability scanning requires external tools (OpenVAS, nmap). Configure separately."}


# ---------------- Utility -------------------------------------------------
def format_result(result):
    try:
        return json.dumps(result, indent=2)
    except Exception:
        return str(result)


# ---------------- GUI App -------------------------------------------------
class NetworkToolApp(App):
    def build(self):
        # Root layout (vertical)
        main_layout = BoxLayout(orientation='vertical', padding=14, spacing=10)

        # Title
        title = Label(
            text='[b]Network Scanner Tool[/b]',
            markup=True,
            font_size=20,
            size_hint_y=None,
            height=36,
            color=(1, 1, 1, 1)
        )
        main_layout.add_widget(title)

        # Input field
        self.input = TextInput(
            hint_text='Enter IP or Network Range (e.g. 192.168.1.0/24 or 192.168.1.5)',
            size_hint_y=None,
            height=44,
            background_color=(0.14, 0.14, 0.14, 1),
            foreground_color=(1, 1, 1, 1),
            cursor_color=(1, 1, 1, 1)
        )
        main_layout.add_widget(self.input)

        # Scrollable area for buttons
        scroll = ScrollView(size_hint=(1, 1))
        grid = GridLayout(cols=1, spacing=10, size_hint_y=None)
        grid.bind(minimum_height=grid.setter('height'))

        # Buttons list
        buttons = [
            ('🔍 Discover Hosts', self.discover_hosts),
            ('🧭 Scan Ports', self.scan_ports),
            ('🧩 Enumerate Services', self.enumerate_services),
            ('🛡 Vulnerability Scan', self.vulnerability_scan),
            ('🌐 Sniff HTTP Packets', self.sniff_http),
            ('🔒 Sniff HTTPS Packets', self.sniff_https),
        ]

        for text, func in buttons:
            btn = Button(
                text=text,
                size_hint_y=None,
                height=58,
                background_color=(0.22, 0.22, 0.22, 1),
                color=(1, 1, 1, 1),
                font_size=15
            )
            btn.bind(on_press=func)
            grid.add_widget(btn)

        # Add grid to scroll and scroll to main layout
        scroll.add_widget(grid)
        main_layout.add_widget(scroll)

        # Status label at bottom
        self.status_label = Label(
            text='Ready',
            size_hint_y=None,
            height=34,
            color=(0.85, 0.85, 0.85, 1)
        )
        main_layout.add_widget(self.status_label)

        return main_layout

    # Generic background runner that updates UI via Clock
    def run_in_thread(self, func, *args, **kwargs):
        def runner():
            try:
                result = func(*args, **kwargs)
                Clock.schedule_once(lambda dt: self._show_result_safe(func.__name__, result))
            except Exception as e:
                Clock.schedule_once(lambda dt: self._show_result_safe("Error", {"error": str(e)}))

        threading.Thread(target=runner, daemon=True).start()

    def _show_result_safe(self, title, result):
        content = format_result(result)
        self.show_popup(title, content)
        self.status_label.text = "Ready"

    # ---------------- Handlers ----------------
    def discover_hosts(self, _):
        self.status_label.text = "Discovering hosts..."
        self.run_in_thread(self._discover_hosts)

    def _discover_hosts(self):
        network_range = self.input.text.strip()
        if not network_range:
            return {"error": "Please enter an IP or network range."}
        if final and hasattr(final, "discover_hosts"):
            try:
                return final.discover_hosts(network_range)
            except Exception as e:
                return {"error": f"final.discover_hosts() error: {e}"}
        return fallback_discover_hosts(network_range)

    def scan_ports(self, _):
        self.status_label.text = "Scanning ports..."
        self.run_in_thread(self._scan_ports)

    def _scan_ports(self):
        host = self.input.text.strip()
        if not host:
            return {"error": "Please enter a host IP for port scanning."}
        if final and hasattr(final, "scan_ports"):
            try:
                return final.scan_ports(host)
            except Exception as e:
                return {"error": f"final.scan_ports() error: {e}"}
        return fallback_scan_ports(host)

    def enumerate_services(self, _):
        self.status_label.text = "Enumerating services..."
        self.run_in_thread(self._enumerate_services)

    def _enumerate_services(self):
        network_range = self.input.text.strip()
        if not network_range:
            return {"error": "Please enter a network range."}
        if final and hasattr(final, "service_enumeration"):
            try:
                return final.service_enumeration(network_range)
            except Exception as e:
                return {"error": f"final.service_enumeration() error: {e}"}
        return fallback_service_enumeration(network_range)

    def vulnerability_scan(self, _):
        self.status_label.text = "Starting vulnerability scan..."
        self.run_in_thread(self._vulnerability_scan)

    def _vulnerability_scan(self):
        network_range = self.input.text.strip()
        if not network_range:
            return {"error": "Please enter a network range."}
        if final and hasattr(final, "vulnerability_scan"):
            try:
                return final.vulnerability_scan(network_range)
            except Exception as e:
                return {"error": f"final.vulnerability_scan() error: {e}"}
        return fallback_vulnerability_scan(network_range)

    # ---------------- Packet sniffing ----------------
    def sniff_http(self, _):
        if not SCAPY_AVAILABLE:
            self.show_popup("Sniff Error", "Scapy not installed. Install scapy to enable sniffing.")
            return
        self.status_label.text = "Sniffing HTTP packets (5s)..."
        self.run_in_thread(self._sniff_packets, "http", 5)

    def sniff_https(self, _):
        if not SCAPY_AVAILABLE:
            self.show_popup("Sniff Error", "Scapy not installed. Install scapy to enable sniffing.")
            return
        self.status_label.text = "Sniffing HTTPS packets (5s)..."
        self.run_in_thread(self._sniff_packets, "https", 5)

    def _sniff_packets(self, mode, duration):
        if not SCAPY_AVAILABLE:
            return {"error": "scapy not available"}
        results = []

        def pkt_cb(pkt):
            try:
                if pkt.haslayer(TCP):
                    src = pkt[IP].src if pkt.haslayer(IP) else None
                    dst = pkt[IP].dst if pkt.haslayer(IP) else None
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    results.append({"src": src, "dst": dst, "sport": sport, "dport": dport})
            except Exception:
                pass

        flt = "tcp and port 80" if mode == "http" else "tcp and port 443"
        try:
            sniff(filter=flt, prn=pkt_cb, timeout=duration)
        except PermissionError:
            return {"error": "Permission denied. Run with admin/root privileges to sniff."}
        except Exception as e:
            return {"error": f"Sniff error: {e}"}

        return {"mode": mode, "captured": len(results), "sample": results[:20]}

    # ---------------- UI helpers ----------------
    def show_popup(self, title, content):
        if isinstance(content, str) and len(content) > 4000:
            content = content[:4000] + "\n\n[output truncated]"
        popup = Popup(title=title, content=Label(text=str(content)), size_hint=(0.9, 0.8))
        popup.open()


if __name__ == '__main__':
    NetworkToolApp().run()
