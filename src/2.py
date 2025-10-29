from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
import nmap
import netifaces as ni


class NetworkScannerApp(App):
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

    def scan_open_ports(self, ip_address):
        nm = nmap.PortScanner()
        try:
            nm.scan(ip_address, arguments='-sS', timeout=10)
            open_ports = []
            for proto in nm[ip_address].all_protocols():
                lport = nm[ip_address][proto].keys()
                for port in sorted(lport):
                    if nm[ip_address][proto][port]['state'] == 'open':
                        open_ports.append(f"Port: {port}, Service: {nm[ip_address][proto][port]['name']}")
            return "\n".join(open_ports) if open_ports else "No open ports found."
        except Exception as e:
            return f"Error scanning ports on {ip_address}: {e}"

    def show_scan_results(self, instance):
        results = self.scan_network()
        popup = Popup(
            title='Scan Results',
            content=Label(text=results),
            size_hint=(0.8, 0.8)
        )
        popup.open()

    def open_port_scan_popup(self, instance):
        # Popup to get the IP address
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

        return layout


if __name__ == '__main__':
    NetworkScannerApp().run()
