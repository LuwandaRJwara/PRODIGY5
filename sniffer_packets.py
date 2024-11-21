from scapy.all import *

# Callback function to process packets
def packet_callback(packet):
    print(f"Packet captured:")
    
    # Extract and display IP-related information (if available)
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst}")
    
    # Extract and display protocol information
    if packet.haslayer(TCP):
        print("Protocol: TCP")
    elif packet.haslayer(UDP):
        print("Protocol: UDP")
    elif packet.haslayer(ICMP):
        print("Protocol: ICMP")
    
    # Display payload data (if available)
    if packet.haslayer(Raw):
        print(f"Payload Data: {packet[Raw].load}")

    print("-" * 50)

# Start sniffing the network
print("Starting packet capture...")
sniff(prn=packet_callback, store=0, filter="ip", count=10)