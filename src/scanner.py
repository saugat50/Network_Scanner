from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
import threading

class NetworkToolApp(App):
    def build(self):
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        self.input = TextInput(hint_text='Enter IP or Network Range', size_hint=(1, 0.1))
        layout.add_widget(self.input)

        buttons = [
            ('Discover Hosts', self.discover_hosts),
            ('Scan Ports', self.scan_ports),
            ('Enumerate Services', self.enumerate_services),
            ('Vulnerability Scan', self.vulnerability_scan)
        ]

        for text, func in buttons:
            btn = Button(text=text, size_hint=(1, 0.1))
            btn.bind(on_press=func)
            layout.add_widget(btn)

        return layout

    def run_in_thread(self, func, *args):
        """Runs a function in a separate thread to prevent GUI freezing."""
        threading.Thread(target=func, args=args, daemon=True).start()

    def discover_hosts(self, _):
        self.run_in_thread(self._discover_hosts)

    def _discover_hosts(self):
        network_range = self.input.text.strip()
        result = final.discover_hosts(network_range)
        self.show_popup("Discover Hosts", str(result))

    def scan_ports(self, _):
        self.run_in_thread(self._scan_ports)

    def _scan_ports(self):
        ip = self.input.text.strip()
        result = final.scan_ports(ip)
        self.show_popup("Scan Ports", str(result))

    def enumerate_services(self, _):
        self.run_in_thread(self._enumerate_services)

    def _enumerate_services(self):
        network_range = self.input.text.strip()
        result = final.service_enumeration(network_range)
        self.show_popup("Enumerate Services", str(result))

    def vulnerability_scan(self, _):
        self.run_in_thread(self._vulnerability_scan)

    def _vulnerability_scan(self):
        network_range = self.input.text.strip()
        result = final.vulnerability_scan(network_range)
        self.show_popup("Vulnerability Scan", str(result))

    def show_popup(self, title, content):
        popup = Popup(title=title, content=Label(text=content), size_hint=(0.8, 0.8))
        popup.open()

if __name__ == '__main__':
    NetworkToolApp().run()
