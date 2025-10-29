from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
import nmap
import netifaces as ni
from scapy.all import sniff, IP, TCP, Raw, send
import re
import threading


class NetworkToolApp(App):
    def build(self):
        self.layout = BoxLayout(orientation="vertical", spacing=10, padding=10)

        # Input for target IP or range
        self.input_field = TextInput(
            hint_text="Enter network range or IP (e.g., 192.168.1.0/24 or 192.168.1.10)",
            size_hint=(1, 0.1),
        )
        self.layout.add_widget(self.input_field)

        # Output area
        self.output_scroll = ScrollView(size_hint=(1, 0.6))
        self.output_label = Label(size_hint_y=None, text="", text_size=(400, None))
        self.output_label.bind(texture_size=self.output_label.setter("size"))
        self.output_scroll.add_widget(self.output_label)
        self.layout.add_widget(self.output_scroll)

        # Buttons
        self.discover_button = Button(text="Discover Hosts", size_hint=(1, 0.1))
        self.discover_button.bind(on_press=self.discover_hosts)
        self.layout.add_widget(self.discover_button)

        self.port_scan_button = Button(text="Scan Ports", size_hint=(1, 0.1))
        self.port_scan_button.bind(on_press=self.scan_ports)
        self.layout.add_widget(self.port_scan_button)

        self.mitm_button = Button(text="Start MITM Attack", size_hint=(1, 0.1))
        self.mitm_button.bind(on_press=self.start_mitm_attack)
        self.layout.add_widget(self.mitm_button)

        return self.layout

    def log_output(self, message):
        """Logs output to the GUI and saves to file."""
        self.output_label.text += f"{message}\n"
        with open("network_tool_log.txt", "a") as log_file:
            log_file.write(f"{message}\n")

    def get_local_network_range(self):
        try:
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
        except Exception as e:
            self.log_output(f"Error getting network range: {e}")
            return None

    def discover_hosts(self, instance):
        """Discovers active hosts in the given network range."""
        target = self.input_field.text or self.get_local_network_range()
        if not target:
            self.log_output("Please provide a valid network range or IP.")
            return

        self.log_output(f"Discovering hosts in range: {target}")
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=target, arguments='-sn')
            hosts = [
                {
                    'IP Address': host,
                    'Hostname': nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else 'Unknown',
                }
                for host in nm.all_hosts()
                if nm[host].state() == 'up'
            ]
            if hosts:
                self.log_output("Discovered hosts:")
                for host in hosts:
                    self.log_output(f"IP: {host['IP Address']}, Hostname: {host['Hostname']}")
            else:
                self.log_output("No active hosts found.")
        except Exception as e:
            self.log_output(f"Error during host discovery: {e}")

    def scan_ports(self, instance):
        """Scans open ports on the specified IP address."""
        target = self.input_field.text
        if not target:
            self.log_output("Please provide a target IP address for port scanning.")
            return

        self.log_output(f"Scanning open ports on {target}...")
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=target, arguments='-sS')
            if target in nm.all_hosts():
                open_ports = []
                for proto in nm[target].all_protocols():
                    ports = nm[target][proto].keys()
                    open_ports.extend(
                        (port, nm[target][proto][port]['name']) for port in ports if nm[target][proto][port]['state'] == 'open'
                    )
                if open_ports:
                    self.log_output(f"Open ports on {target}:")
                    for port, service in open_ports:
                        self.log_output(f"Port: {port}, Service: {service}")
                else:
                    self.log_output(f"No open ports found on {target}.")
            else:
                self.log_output(f"{target} is not active.")
        except Exception as e:
            self.log_output(f"Error during port scan: {e}")

    def packet_callback(self, packet):
        """Handles packets for HTTP MITM attack."""
        if IP in packet and TCP in packet:
            if packet[TCP].dport == 80 and packet.haslayer(Raw) and b"GET" in packet[Raw].load:
                url = re.search(b"(?i)\\bHost:\\s*(.*?)\\r\\n", packet[Raw].load)
                if url:
                    self.log_output(f"HTTP GET request to: {url.group(1).decode()}")

    def start_mitm_attack(self, instance):
        """Starts a MITM attack on the specified target IP."""
        target = self.input_field.text
        if not target:
            self.log_output("Please provide a target IP address for MITM attack.")
            return

        self.log_output(f"Starting MITM attack on HTTP traffic from {target}...")
        threading.Thread(target=lambda: sniff(filter=f"ip host {target} and tcp port 80", prn=self.packet_callback, store=False)).start()


if __name__ == "__main__":
    NetworkToolApp().run()
