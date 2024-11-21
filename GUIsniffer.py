import tkinter as tk
from tkinter import scrolledtext
from scapy.all import *
import threading

# Global variable to control sniffing

sniffing = False

# Callback function to process captured packets
def packet_callback(packet):
    if sniffing:  # Only show packets if sniffing is active
        # Print packet summary for debugging purposes
        print(f"Packet captured: {packet.summary()}")
        
        # Check if the packet has an IP layer
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet.proto
            display_packet(ip_src, ip_dst, protocol)

# Function to display packet info in the text area
def display_packet(src, dst, protocol):
    packet_info = f"Source IP: {src} -> Destination IP: {dst} | Protocol: {protocol}\n"
    text_area.insert(tk.END, packet_info)
    text_area.yview(tk.END)  # Auto-scroll to the bottom

# Function to start sniffing packets in a separate thread
def start_sniffing():
    global sniffing
    sniffing = True
    start_button.config(state=tk.DISABLED)  # Disable start button while sniffing
    stop_button.config(state=tk.NORMAL)    # Enable stop button
    # Start sniffing in a new thread to keep the GUI responsive
    print("Starting packet sniffing...")
    thread = threading.Thread(target=sniff_packets)
    thread.daemon = True  # Daemon thread will close when the main program exits
    thread.start()

# Function to stop sniffing
def stop_sniffing():
    global sniffing
    sniffing = False
    start_button.config(state=tk.NORMAL)  # Enable start button
    stop_button.config(state=tk.DISABLED)  # Disable stop button
    print("Packet sniffing stopped.")

# Function to sniff packets
def sniff_packets():
    try:
        # Set up packet sniffing
        print("Sniffing packets...")
        sniff(prn=packet_callback, store=0, filter="ip", count=0)
    except Exception as e:
        print(f"Error while sniffing: {e}")

# Set up the GUI window
root = tk.Tk()
root.title("Packet Sniffer")
root.geometry("600x400")

# Start button
start_button = tk.Button(root, text="Start Sniffing", width=20, command=start_sniffing)
start_button.pack(pady=10)

# Stop button
stop_button = tk.Button(root, text="Stop Sniffing", width=20, state=tk.DISABLED, command=stop_sniffing)
stop_button.pack(pady=10)

# Scrollable text area for packet info
text_area = scrolledtext.ScrolledText(root, width=70, height=15)
text_area.pack(pady=10)

# Run the GUI event loop
root.mainloop()
