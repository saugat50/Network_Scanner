from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.label import Label
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

    def show_scan_results(self, instance):
        results = self.scan_network()
        popup = Popup(
            title='Scan Results',
            content=Label(text=results),
            size_hint=(0.8, 0.8)
        )
        popup.open()

    def build(self):
        layout = BoxLayout(orientation='vertical', spacing=10, padding=20)
        scan_button = Button(text='Scan', size_hint=(1, 0.2))
        scan_button.bind(on_release=self.show_scan_results)
        layout.add_widget(scan_button)
        return layout


if __name__ == '__main__':
    NetworkScannerApp().run()
