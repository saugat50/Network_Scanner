from kivy.lang import Builder
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivymd.app import MDApp
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.card import MDCard
from kivymd.uix.dialog import MDDialog
from kivymd.uix.screen import Screen
import nmap
import netifaces as ni
from scapy.all import sniff, Raw, IP, TCP, re

KV = """
Screen:
    MDBoxLayout:
        orientation: 'vertical'
        padding: dp(20)
        spacing: dp(15)

        MDLabel:
            text: "Network Scanner App"
            theme_text_color: "Primary"
            font_style: "H5"
            halign: "center"

        ScrollView:
            MDBoxLayout:
                orientation: 'vertical'
                spacing: dp(10)
                padding: dp(10)

                MDRaisedButton:
                    text: "Scan Network"
                    on_release: app.show_scan_results()

                MDRaisedButton:
                    text: "Search Open Ports"
                    on_release: app.open_port_scan_popup()

                MDRaisedButton:
                    text: "Enumerate Services"
                    on_release: app.enumerate_services_popup()

                MDRaisedButton:
                    text: "Vulnerability Scan"
                    on_release: app.vulnerability_scan_popup()

                MDRaisedButton:
                    text: "Sniff HTTP Packets"
                    on_release: app.sniff_packets_popup()

                MDRaisedButton:
                    text: "Sniff HTTPS Packets"
                    on_release: app.sniff_https_packets_popup()
"""

class NetworkScannerApp(MDApp):
    def build(self):
        self.theme_cls.primary_palette = "Blue"
        return Builder.load_string(KV)

    def show_popup(self, title, text):
        dialog = MDDialog(title=title, text=text, size_hint=(0.8, 0.8))
        dialog.open()

    def show_scan_results(self):
        results = self.scan_network()
        self.show_popup("Scan Results", results)

    def scan_network(self):
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts='192.168.1.0/24', arguments='-sn')
            results = [f"IP: {host}, State: {nm[host].state()}" for host in nm.all_hosts()]
            return "\n".join(results) if results else "No devices found."
        except Exception as e:
            return f"Error scanning network: {e}"

    def open_port_scan_popup(self):
        self.show_input_popup("Enter IP Address", self.scan_open_ports)

    def scan_open_ports(self, ip_address):
        try:
            nm = nmap.PortScanner()
            nm.scan(ip_address, arguments='-sS')
            open_ports = [f"Port {port}: {nm[ip_address]['tcp'][port]['name']}" for port in nm[ip_address]['tcp'] if nm[ip_address]['tcp'][port]['state'] == 'open']
            self.show_popup("Open Ports", "\n".join(open_ports) if open_ports else "No open ports found.")
        except Exception as e:
            self.show_popup("Error", f"Error scanning ports: {e}")

    def show_input_popup(self, hint, callback):
        layout = BoxLayout(orientation='vertical', spacing=10, padding=10)
        input_field = TextInput(hint_text=hint, multiline=False)
        send_button = Button(text="Submit", size_hint=(1, None), height=40)

        def on_submit(instance):
            callback(input_field.text)
            popup.dismiss()

        send_button.bind(on_release=on_submit)
        layout.add_widget(input_field)
        layout.add_widget(send_button)
        popup = Popup(title=hint, content=layout, size_hint=(0.8, 0.4))
        popup.open()

if __name__ == '__main__':
    NetworkScannerApp().run()
