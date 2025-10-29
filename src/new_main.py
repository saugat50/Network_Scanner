import nmap
import netifaces as ni
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
import threading

class NetworkScannerApp(App):
    def build(self):
        self.layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        self.scan_button = Button(text="Scan Network", size_hint=(1, 0.1))
        self.scan_button.bind(on_press=self.scan_network)
        self.layout.add_widget(self.scan_button)

        self.results_label = Label(text="Click 'Scan Network' to begin.", size_hint=(1, 0.1))
        self.layout.add_widget(self.results_label)

        self.results_view = ScrollView(size_hint=(1, 0.8))
        self.results_layout = GridLayout(cols=1, size_hint_y=None)
        self.results_layout.bind(minimum_height=self.results_layout.setter('height'))
        self.results_view.add_widget(self.results_layout)
        self.layout.add_widget(self.results_view)

        return self.layout

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
            return f"Error: {e}"

    def scan_network(self, instance):
        self.results_label.text = "Scanning... Please wait."
        threading.Thread(target=self.perform_scan).start()

    def perform_scan(self):
        network_range = self.get_local_network_range()
        if "Error" in network_range:
            self.update_results([{"Error": network_range}])
            return

        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=network_range, arguments='-sn')
            connected_devices = []

            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    mac_address = nm[host]['addresses'].get('mac', 'N/A')
                    hostname = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else 'N/A'
                    connected_devices.append({
                        'IP Address': host,
                        'MAC Address': mac_address,
                        'Hostname': hostname
                    })

            self.update_results(connected_devices)
        except Exception as e:
            self.update_results([{"Error": f"Scanning failed: {e}"}])

    def update_results(self, results):
        self.results_layout.clear_widgets()

        if len(results) == 0:
            self.results_label.text = "No devices found."
            return

        for device in results:
            if "Error" in device:
                error_label = Label(text=device["Error"], size_hint_y=None, height=30)
                self.results_layout.add_widget(error_label)
            else:
                device_info = f"IP: {device['IP Address']}, MAC: {device['MAC Address']}, Hostname: {device['Hostname']}"
                device_label = Label(text=device_info, size_hint_y=None, height=30)
                self.results_layout.add_widget(device_label)

        self.results_label.text = "Scan Complete. Results below."

if __name__ == "__main__":
    NetworkScannerApp().run()
