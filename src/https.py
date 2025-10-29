from scapy.all import sniff, IP, TCP, Raw
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.clock import Clock
import threading
import struct

class HTTPSnifferApp(App):
    def extract_sni(self, raw_data):
        try:
            # TLS Handshake starts with 0x16 (Content Type: Handshake)
            if raw_data[0] == 0x16:
                # Skip to the handshake message, extract SNI length
                sni_start = raw_data.find(b'\x00\x00')
                if sni_start != -1:
                    sni_start += 2
                    sni_length = struct.unpack("!H", raw_data[sni_start:sni_start + 2])[0]
                    sni_start += 2
                    return raw_data[sni_start:sni_start + sni_length].decode('utf-8', errors='ignore')
        except Exception as e:
            return f"Error extracting SNI: {e}"
        return None

    def sniff_https_packets(self, ip_address):
        captured_domains = []

        def process_packet(packet):
            # Check for IP, TCP, and Raw layers
            if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
                if ip_address in (packet[IP].src, packet[IP].dst):
                    raw_data = packet[Raw].load
                    sni = self.extract_sni(raw_data)
                    if sni:
                        captured_domains.append(f"HTTPS Domain: {sni}")

        try:
            # Sniff on the specified IP address and port 443 (HTTPS)
            sniff(filter=f"ip host {ip_address} and tcp port 443", prn=process_packet, timeout=30)
            return "\n".join(captured_domains) if captured_domains else "No HTTPS domains found."
        except Exception as e:
            return f"Error sniffing HTTPS packets: {e}"

    def show_sniff_results(self, sniffed_data):
        # Display the sniffed data in a popup
        popup = Popup(
            title='Sniffed HTTPS Domains',
            content=Label(text=sniffed_data),
            size_hint=(0.8, 0.8)
        )
        popup.open()

    def sniff_https_packets_popup(self, instance):
        input_layout = BoxLayout(orientation='horizontal', spacing=10, padding=10)
        ip_input = TextInput(hint_text="Enter IP address", multiline=False, size_hint=(0.7, 1))
        send_button = Button(text="Sniff", size_hint=(0.3, 1))

        def on_sniff(instance):
            ip_address = ip_input.text
            if ip_address:
                # Run sniffing in a separate thread
                def sniff_thread():
                    sniffed_data = self.sniff_https_packets(ip_address)
                    # Schedule UI update in the main thread
                    Clock.schedule_once(lambda dt: self.show_sniff_results(sniffed_data), 0)

                thread = threading.Thread(target=sniff_thread)
                thread.daemon = True
                thread.start()

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
        sniff_button = Button(text='Sniff HTTPS Packets', size_hint=(1, 0.2))
        sniff_button.bind(on_release=self.sniff_https_packets_popup)
        layout.add_widget(sniff_button)
        return layout

if __name__ == '__main__':
    HTTPSnifferApp().run()
