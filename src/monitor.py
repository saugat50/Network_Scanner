from scapy.all import sniff, DNS, DNSQR, IP
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.clock import Clock
import threading


class NetworkMonitorApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.monitored_domains = []
        self.is_sniffing = False
        self.target_ip = None

    def start_sniffing(self):
        if not self.target_ip:
            self.show_error_popup("Please enter an IP address first!")
            return

        self.is_sniffing = True
        self.monitored_domains = []

        def process_packet(packet):
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    # Only monitor traffic involving the target IP
                    if self.target_ip in [src_ip, dst_ip]:
                        domain_name = packet[DNSQR].qname.decode('utf-8')
                        if domain_name not in self.monitored_domains:
                            self.monitored_domains.append(domain_name)
                            # Schedule UI update
                            Clock.schedule_once(lambda dt: self.update_monitor_label())

        def sniff_thread():
            try:
                sniff(
                    filter=f"udp port 53 and host {self.target_ip}",
                    prn=process_packet,
                    stop_filter=lambda _: not self.is_sniffing
                )
            except Exception as e:
                Clock.schedule_once(lambda dt: self.show_error_popup(f"Error: {e}"))

        threading.Thread(target=sniff_thread, daemon=True).start()

    def stop_sniffing(self):
        self.is_sniffing = False

    def update_monitor_label(self):
        self.monitor_label.text = "\n".join(self.monitored_domains) or "No domains monitored yet."

    def show_error_popup(self, message):
        popup = Popup(
            title="Error",
            content=Label(text=message),
            size_hint=(0.8, 0.4)
        )
        popup.open()

    def build(self):
        layout = BoxLayout(orientation='vertical', spacing=10, padding=20)

        # Input box for IP address
        ip_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.1), spacing=10)
        self.ip_input = TextInput(hint_text="Enter IP address to monitor", multiline=False)
        set_ip_button = Button(text="Set IP", size_hint=(0.3, 1))
        set_ip_button.bind(on_release=lambda _: self.set_target_ip())
        ip_layout.add_widget(self.ip_input)
        ip_layout.add_widget(set_ip_button)
        layout.add_widget(ip_layout)

        # Label to show monitored domains
        self.monitor_label = Label(text="Monitoring websites...", size_hint=(1, 0.6))
        layout.add_widget(self.monitor_label)

        # Control buttons
        control_layout = BoxLayout(orientation='horizontal', spacing=10, size_hint=(1, 0.2))
        start_button = Button(text="Start Monitoring", size_hint=(0.5, 1))
        stop_button = Button(text="Stop Monitoring", size_hint=(0.5, 1))

        start_button.bind(on_release=lambda _: self.start_sniffing())
        stop_button.bind(on_release=lambda _: self.stop_sniffing())

        control_layout.add_widget(start_button)
        control_layout.add_widget(stop_button)

        layout.add_widget(control_layout)
        return layout

    def set_target_ip(self):
        ip = self.ip_input.text.strip()
        if ip:
            self.target_ip = ip
            self.show_error_popup(f"Target IP set to {ip}")
        else:
            self.show_error_popup("Invalid IP address!")


if __name__ == '__main__':
    NetworkMonitorApp().run()
