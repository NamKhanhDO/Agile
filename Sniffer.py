import logging
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk
from collections import defaultdict
from scapy.all import sniff, DNS, TCP, IP, Raw, DNSQR, DNSRR, get_if_list, IPv6  # Added IPv6 import
from scapy.config import conf
conf.use_pcap = True

# Set up logging for the IDS
logging.basicConfig(filename='ids_alerts.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Counters and thresholds
syn_counter = defaultdict(int)
time_window = 60  # seconds
syn_threshold = 100

# IDS Functions
def log_suspicious_activity(message, packet):
    """Logs suspicious activity with packet details."""
    packet_info = packet.summary() if packet else "No packet data"
    logging.info(f"{message} | Packet: {packet_info}")
    gui_output_suspicious(f"[+] {message} | Packet: {packet_info}\n")

def gui_output_packet_trace(message):
    """Show real-time packet trace in the packet trace text area."""
    packet_trace_area.insert(tk.END, message)
    packet_trace_area.see(tk.END)  # Automatically scroll to the end

def gui_output_suspicious(message):
    """Show suspicious activities in the suspicious activity text area."""
    suspicious_area.insert(tk.END, message, "red_text")
    suspicious_area.see(tk.END)  # Automatically scroll to the end

def detect_dns_tunneling(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(DNSQR):
        for i in range(packet[DNS].ancount):
            if packet[DNSRR].type == 16 and len(packet[DNSRR].rdata) > 100:
                log_suspicious_activity("Suspicious activity detected: DNS Tunneling", packet)

def detect_ssh_tunneling(packet):
    if packet.haslayer(TCP) and (packet[TCP].sport > 1024 or packet[TCP].dport > 1024) and 'ssh' in str(packet).lower():
        log_suspicious_activity("Suspicious activity detected: SSH Tunneling", packet)

def monitor_syn_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        # Check if the packet has an IPv4 layer
        if packet.haslayer(IP):
            ip_src = packet[IP].src
        # Check if the packet has an IPv6 layer
        elif packet.haslayer(IPv6):
            ip_src = packet[IPv6].src
        else:
            # If neither IP nor IPv6 is present, skip processing
            return

        # Increment the SYN count for the source IP
        syn_counter[ip_src] += 1
        
        # Check if the SYN threshold is exceeded
        if syn_counter[ip_src] > syn_threshold:
            log_suspicious_activity(f"SYN Flood Attack detected from {ip_src}", packet)
            syn_counter[ip_src] = 0

def keyword_detection(packet):
    suspicious_keywords = ["password", "login", "admin", "root", "bank", "credit", "card", "paypal", "malware", "virus", "trojan"]
    if packet.haslayer(Raw):
        payload = str(packet[Raw].load).lower()
        for keyword in suspicious_keywords:
            if keyword in payload:
                log_suspicious_activity(f"Suspicious keyword detected: {keyword}", packet)
                break

# Main IDS function
def packet_callback(packet):
    # Display the packet trace in real time
    gui_output_packet_trace(f"Packet captured: {packet.summary()}\n")
    
    # Perform various detections
    detect_dns_tunneling(packet)
    detect_ssh_tunneling(packet)
    monitor_syn_flood(packet)
    keyword_detection(packet)

# Function to start monitoring network in a separate thread
def start_monitoring():
    iface = interface_combobox.get()  # Get the selected network interface from the dropdown
    if iface:
        gui_output_suspicious(f"[+] IDS is running... Monitoring traffic on {iface} in real-time.\n")
        # Start the sniffing in a new thread
        sniff_thread = threading.Thread(target=lambda: sniff(iface=iface, prn=packet_callback, store=0))
        sniff_thread.daemon = True  # Ensures the thread will close when the main program exits
        sniff_thread.start()
    else:
        gui_output_suspicious("[!] Please select a network interface to start monitoring.\n")

# GUI Setup using Tkinter
root = tk.Tk()
root.title("Simple IDS Application")
root.geometry("850x600")

# Interface Selection
interface_label = tk.Label(root, text="Select Network Interface:")
interface_label.pack()

interfaces = get_if_list()  # Get the list of available network interfaces

# Manually add "Wi-Fi" if it's not in the list
if "Wi-Fi" not in interfaces:
    interfaces.append("Wi-Fi")

interface_combobox = ttk.Combobox(root, values=interfaces)
interface_combobox.pack()

# Start Button
start_button = tk.Button(root, text="Start Monitoring", command=start_monitoring)
start_button.pack()

# Frame for both packet trace and suspicious activity
frame = tk.Frame(root)
frame.pack(pady=10, fill=tk.BOTH, expand=True)

# Packet Trace Scrolled Text Area
packet_trace_label = tk.Label(frame, text="Packet Trace (Real-Time):")
packet_trace_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

packet_trace_area = scrolledtext.ScrolledText(frame, width=50, height=20)
packet_trace_area.grid(row=1, column=0, padx=5, pady=5)

# Suspicious Activity Scrolled Text Area
suspicious_label = tk.Label(frame, text="Suspicious Activities:")
suspicious_label.grid(row=0, column=1, padx=5, pady=5, sticky="w")

suspicious_area = scrolledtext.ScrolledText(frame, width=50, height=20)
suspicious_area.grid(row=1, column=1, padx=5, pady=5)

# Configure red text tag for suspicious activity
suspicious_area.tag_configure("red_text", foreground="red")

# Run the GUI application
root.mainloop()
