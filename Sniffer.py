#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import time
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk
from collections import defaultdict
from scapy.all import sniff, DNS, TCP, UDP, IP, IPv6, Raw, DNSQR, DNSRR, get_if_list
from scapy.layers.inet6 import IPv6ExtHdrFragment

# Set up logging for the IDS
logging.basicConfig(filename='ids_alerts.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Counters and thresholds
syn_counter = defaultdict(int)
slowloris_counter = defaultdict(int)
time_window = 60  # seconds
syn_threshold = 100
slowloris_threshold = 100

# IDS Functions
def log_suspicious_activity(message, packet=None):
    logging.info(f"{message}")
    gui_output(f"[+] {message}\n")

def gui_output(message):
    text_area.insert(tk.END, message)
    text_area.see(tk.END)  # Automatically scroll to the end

def detect_dns_tunneling(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet.haslayer(DNSQR):
        for i in range(packet[DNS].ancount):
            if packet[DNSRR].type == 16 and len(packet[DNSRR].rdata) > 100:
                log_suspicious_activity("Suspicious activity detected: DNS Tunneling")

def detect_ssh_tunneling(packet):
    if packet.haslayer(TCP) and (packet[TCP].sport > 1024 or packet[TCP].dport > 1024) and 'ssh' in str(packet).lower():
        log_suspicious_activity("Suspicious activity detected: SSH Tunneling")

def monitor_syn_flood(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        ip_src = packet[IP].src
        syn_counter[ip_src] += 1
        
        if syn_counter[ip_src] > syn_threshold:
            log_suspicious_activity(f"SYN Flood Attack detected from {ip_src}")
            syn_counter[ip_src] = 0

def keyword_detection(packet):
    suspicious_keywords = ["password", "login", "admin", "root", "bank", "credit", "card", "paypal", "malware", "virus", "trojan"]
    if packet.haslayer(Raw):
        payload = str(packet[Raw].load).lower()
        for keyword in suspicious_keywords:
            if keyword in payload:
                log_suspicious_activity(f"Suspicious keyword detected: {keyword}")
                break

# Main IDS function
def packet_callback(packet):
    detect_dns_tunneling(packet)
    detect_ssh_tunneling(packet)
    monitor_syn_flood(packet)
    keyword_detection(packet)

# Function to start monitoring network in a separate thread
def start_monitoring():
    iface = interface_combobox.get()  # Get the selected network interface from the dropdown
    if iface:
        gui_output(f"[+] IDS is running... Monitoring traffic on {iface} in real-time.\n")
        # Start the sniffing in a new thread
        sniff_thread = threading.Thread(target=lambda: sniff(iface=iface, prn=packet_callback, store=0))
        sniff_thread.daemon = True  # Ensures the thread will close when the main program exits
        sniff_thread.start()
    else:
        gui_output("[!] Please select a network interface to start monitoring.\n")

# GUI Setup using Tkinter
root = tk.Tk()
root.title("Simple IDS Application")
root.geometry("600x400")

# Interface Selection
interface_label = tk.Label(root, text="Select Network Interface:")
interface_label.pack()

# Dropdown for selecting network interfaces
interfaces = get_if_list()  # Get the list of available network interfaces

# Manually add "Wi-Fi" if it's not in the list
if "Wi-Fi" not in interfaces:
    interfaces.append("Wi-Fi")

interface_combobox = ttk.Combobox(root, values=interfaces)
interface_combobox.pack()

# Start Button
start_button = tk.Button(root, text="Start Monitoring", command=start_monitoring)
start_button.pack()

# Scrolled Text Area for Displaying Logs
text_area = scrolledtext.ScrolledText(root, width=70, height=20)
text_area.pack()

# Run the GUI application
root.mainloop()
