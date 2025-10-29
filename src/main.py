from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.clock import Clock
import nmap
import netifaces as ni
from scapy.all import sniff, Raw, IP, TCP, re


class NetworkScannerApp(App):
    # Get the local network range based on the default gateway and subnet mask
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
            return None

    # Scan the network to discover active devices
    def scan_network(self):
        network_range = self.get_local_network_range()
        if not network_range:
            return "Error retrieving network range."
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=network_range, arguments='-sn')
        except Exception as e:
            return f"Error during scanning: {e}"
        results = []
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                mac_address = nm[host]['addresses'].get('mac', 'Unknown')
                hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else 'Unknown'
                results.append(f"IP: {host}, MAC: {mac_address}, Hostname: {hostname}")
        return "\n".join(results) if results else "No devices found."

    # Scan open ports on a given IP address
    def scan_open_ports(self, ip_address):
        nm = nmap.PortScanner()
        try:
            nm.scan(ip_address, arguments='-sS', timeout=30)
            open_ports = []
            for proto in nm[ip_address].all_protocols():
                lport = nm[ip_address][proto].keys()
                for port in sorted(lport):
                    if nm[ip_address][proto][port]['state'] == 'open':
                        open_ports.append(f"Port: {port}, Service: {nm[ip_address][proto][port]['name']}")
            return "\n".join(open_ports) if open_ports else "No open ports found."
        except Exception as e:
            return f"Error scanning ports on {ip_address}: {e}"

    # Enumerate running services on network devices
    def enumerate_services(self, ip_range):
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip_range, arguments='-sV --host-timeout 60m')
            results = []
            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            service = nm[host][proto][port]
                            results.append(
                                f"Host: {host}, Port: {port}/{proto}, Service: {service['name']}, Version: {service.get('version', 'Unknown')}"
                            )
            return "\n".join(results) if results else "No services found."
        except Exception as e:
            return f"Error enumerating services on {ip_range}: {e}"

    # Perform vulnerability scanning on a given IP address
    def scan_vulnerability(self, ip_address):
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip_address, arguments='-Pn --script vuln')
            results = []
            for host in nm.all_hosts():
                for script in nm[host].get('hostscript', []):
                    results.append(f"Script: {script['id']}, Output: {script['output']}")
            return "\n".join(results) if results else "No vulnerabilities found."
        except Exception as e:
            return f"Error scanning vulnerabilities on {ip_address}: {e}"

    # Sniff HTTP packets from the network
    def sniff_http_packets(self, ip_address):
        sniffed_data = []

        def packet_callback(packet):
            if packet.haslayer(Raw):
                http_payload = packet[Raw].load
                sniffed_data.append(f"HTTP Packet: {http_payload.decode(errors='ignore')}")
        
        try:
            print(f"Starting HTTP packet sniffing on {ip_address}...")
            sniff(filter=f"tcp and host {ip_address} and port 80", prn=packet_callback, store=0, timeout=30)
            return "\n".join(sniffed_data) if sniffed_data else "No HTTP packets captured."
        except Exception as e:
            return f"Error sniffing HTTP packets: {e}"

    def show_scan_results(self, instance):
        results = self.scan_network()
        popup = Popup(
            title='Scan Results',
            content=Label(text=results),
            size_hint=(0.8, 0.8)
        )
        popup.open()

    def open_port_scan_popup(self, instance):
        input_layout = BoxLayout(orientation='horizontal', spacing=10, padding=10)
        ip_input = TextInput(hint_text="Enter IP address", multiline=False, size_hint=(0.7, 1))
        send_button = Button(text="Send", size_hint=(0.3, 1))

        def on_send(instance):
            ip_address = ip_input.text
            if ip_address:
                open_ports = self.scan_open_ports(ip_address)
                result_popup = Popup(
                    title='Open Ports',
                    content=Label(text=open_ports),
                    size_hint=(0.8, 0.8)
                )
                result_popup.open()
            popup.dismiss()

        send_button.bind(on_release=on_send)
        input_layout.add_widget(ip_input)
        input_layout.add_widget(send_button)
        popup = Popup(
            title="Enter IP Address",
            content=input_layout,
            size_hint=(0.8, 0.4)
        )
        popup.open()

    def enumerate_services_popup(self, instance):
        input_layout = BoxLayout(orientation='horizontal', spacing=10, padding=10)
        ip_input = TextInput(hint_text="e.g., 192.168.1.0/24", multiline=False, size_hint=(0.7, 1))
        send_button = Button(text="Send", size_hint=(0.3, 1))

        def on_send(instance):
            ip_range = ip_input.text
            if ip_range:
                services = self.enumerate_services(ip_range)
                result_popup = Popup(
                    title='Enumerated Services',
                    content=Label(text=services),
                    size_hint=(0.8, 0.8)
                )
                result_popup.open()
            popup.dismiss()

        send_button.bind(on_release=on_send)
        input_layout.add_widget(ip_input)
        input_layout.add_widget(send_button)
        popup = Popup(
            title="Enter IP Range",
            content=input_layout,
            size_hint=(0.8, 0.4)
        )
        popup.open()

    def vulnerability_scan_popup(self, instance):
        input_layout = BoxLayout(orientation='horizontal', spacing=10, padding=10)
        ip_input = TextInput(hint_text="Enter IP address", multiline=False, size_hint=(0.7, 1))
        send_button = Button(text="Send", size_hint=(0.3, 1))

        def on_send(instance):
            ip_address = ip_input.text
            if ip_address:
                vulnerabilities = self.scan_vulnerability(ip_address)
                result_popup = Popup(
                    title='Vulnerability Scan Results',
                    content=Label(text=vulnerabilities),
                    size_hint=(0.8, 0.8)
                )
                result_popup.open()
            popup.dismiss()

        send_button.bind(on_release=on_send)
        input_layout.add_widget(ip_input)
        input_layout.add_widget(send_button)
        popup = Popup(
            title="Enter IP Address",
            content=input_layout,
            size_hint=(0.8, 0.4)
        )
        popup.open()

    def sniff_http_packets(self, ip_address):
        try:
            captured_packets = []

            def process_packet(packet):
                if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
                    if ip_address in (packet[IP].src, packet[IP].dst):
                        http_data = packet[Raw].load.decode('utf-8', errors='ignore')
                        captured_packets.append(f"HTTP Packet: {http_data[:100]}...")

            sniff(filter=f"ip host {ip_address} and tcp port 80", prn=process_packet, count=10, timeout=30)
            return "\n".join(captured_packets) if captured_packets else "No HTTP packets found."
        except Exception as e:
            return f"Error sniffing packets: {e}"

    def show_scan_results(self, instance):
        results = self.scan_network()
        popup = Popup(
            title='Scan Results',
            content=Label(text=results),
            size_hint=(0.8, 0.8)
        )
        popup.open()

    def sniff_packets_popup(self, instance):
        input_layout = BoxLayout(orientation='horizontal', spacing=10, padding=10)
        ip_input = TextInput(hint_text="Enter IP address", multiline=False, size_hint=(0.7, 1))
        send_button = Button(text="Sniff", size_hint=(0.3, 1))

        def on_sniff(instance):
            ip_address = ip_input.text
            if ip_address:
                sniff_results = self.sniff_http_packets(ip_address)
                result_popup = Popup(
                    title='Sniffed HTTP Packets',
                    content=Label(text=sniff_results),
                    size_hint=(0.8, 0.8)
                )
                result_popup.open()
            popup.dismiss()

        send_button.bind(on_release=on_sniff)
        input_layout.add_widget(ip_input)
        input_layout.add_widget(send_button)

        popup = Popup(
            title="Enter IP Address", content=input_layout, size_hint=(0.8, 0.4)
        )
        popup.open()

    def build(self):
        layout = BoxLayout(orientation='vertical', spacing=10, padding=20)


    # Sniff HTTPS packets from the network
    def sniff_https_packets(self, ip_address):
        try:
            captured_packets = []

            def process_packet(packet):
                if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
                    if ip_address in (packet[IP].src, packet[IP].dst):
                        raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                        # Use regex to extract domain names from the data
                        domains = re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', raw_data)
                        if domains:
                            captured_packets.append(f"HTTPS Domain: {', '.join(domains)}")

            # Sniff on the specified IP address and port 443 (HTTPS)
            sniff(filter=f"ip host {ip_address} and tcp port 443", prn=process_packet, timeout=30)
            return "\n".join(captured_packets) if captured_packets else "No HTTPS packets found."
        except Exception as e:
            return f"Error sniffing HTTPS packets: {e}"

    def sniff_https_packets_popup(self, instance):
        input_layout = BoxLayout(orientation='horizontal', spacing=10, padding=10)
        ip_input = TextInput(hint_text="Enter IP address", multiline=False, size_hint=(0.7, 1))
        send_button = Button(text="Sniff", size_hint=(0.3, 1))

        def on_sniff(instance):
            ip_address = ip_input.text
            if ip_address:
                sniff_results = self.sniff_https_packets(ip_address)
                result_popup = Popup(
                    title='Sniffed HTTPS Packets',
                    content=Label(text=sniff_results),
                    size_hint=(0.8, 0.8)
                )
                result_popup.open()
            popup.dismiss()

        send_button.bind(on_release=on_sniff)
        input_layout.add_widget(ip_input)
        input_layout.add_widget(send_button)

        popup = Popup(
            title="Enter IP Address", content=input_layout, size_hint=(0.8, 0.4)
        )
        popup.open()

    def build(self):
        layout = BoxLayout(orientation='vertical', spacing=10, padding=20)

        # Scan network button
        scan_button = Button(text='Scan Network', size_hint=(1, 0.2))
        scan_button.bind(on_release=self.show_scan_results)
        layout.add_widget(scan_button)

        # Search open ports button
        port_scan_button = Button(text='Search Open Ports', size_hint=(1, 0.2))
        port_scan_button.bind(on_release=self.open_port_scan_popup)
        layout.add_widget(port_scan_button)

        # Enumerate services button
        enumerate_services_button = Button(text='Enumerate Services', size_hint=(1, 0.2))
        enumerate_services_button.bind(on_release=self.enumerate_services_popup)
        layout.add_widget(enumerate_services_button)

        # Vulnerability scan button
        vulnerability_scan_button = Button(text='Vulnerability Scan', size_hint=(1, 0.2))
        vulnerability_scan_button.bind(on_release=self.vulnerability_scan_popup)
        layout.add_widget(vulnerability_scan_button)

        # Sniff HTTP Packets button
        sniff_button = Button(text='Sniff HTTP Packets', size_hint=(1, 0.2))
        sniff_button.bind(on_release=self.sniff_packets_popup)
        layout.add_widget(sniff_button)

        # Sniff HTTPS Packets button
        sniff_https_button = Button(text='Sniff HTTPS Packets', size_hint=(1, 0.2))
        sniff_https_button.bind(on_release=self.sniff_https_packets_popup)
        layout.add_widget(sniff_https_button)

        return layout

if __name__ == '__main__':
    NetworkScannerApp().run()
