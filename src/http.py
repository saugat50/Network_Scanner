from scapy.all import sniff, IP, TCP, Raw
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.clock import Clock
import threading

class PacketSnifferApp(App):
    def sniff_http_packets(self, ip_address):
        captured_packets = []

        def process_packet(packet):
            # Check for IP, TCP, and Raw layers
            if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
                if ip_address in (packet[IP].src, packet[IP].dst):
                    try:
                        # Extract HTTP data
                        http_data = packet[Raw].load.decode('utf-8', errors='ignore')
                        captured_packets.append(f"HTTP Packet: {http_data[:300]}...")
                    except Exception as e:
                        captured_packets.append(f"Error processing packet: {e}")

        try:
            # Start sniffing packets
            sniff(filter=f"ip host {ip_address} and tcp port 80", prn=process_packet, timeout=30)
            return "\n".join(captured_packets) if captured_packets else "No HTTP packets captured."
        except Exception as e:
            return f"Error sniffing packets: {e}"

    def show_sniff_results(self, sniffed_data):
        # Display the sniffed data in a popup
        popup = Popup(
            title='Sniffed HTTP Packets',
            content=Label(text=sniffed_data),
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
                # Run sniffing in a separate thread
                def sniff_thread():
                    sniffed_data = self.sniff_http_packets(ip_address)
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
        sniff_button = Button(text='Sniff HTTP Packets', size_hint=(1, 0.2))
        sniff_button.bind(on_release=self.sniff_packets_popup)
        layout.add_widget(sniff_button)
        return layout

if __name__ == '__main__':
    PacketSnifferApp().run()
