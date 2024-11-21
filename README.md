Network Packet Analyzer
Project Overview

The Network Packet Analyzer is a tool designed to capture and analyze network packets transmitted over a local network or the internet.
It allows users to inspect various network protocols, including TCP, UDP, ICMP, and others. 
This tool displays useful information such as source and destination IP addresses, ports, protocols, packet sizes, and payload data. 
The purpose of this project is to aid in educational and research activities related to networking, security, and traffic analysis.

Note:
This tool is intended for ethical and legal use only. 
It should be used in a controlled environment, such as in your own network or on networks where you have explicit permission to monitor traffic.
Features

  Packet Capture: Capture network packets in real-time from the network interface.
  Protocol Analysis: Decode and display common network protocols (e.g., TCP, UDP, ICMP).
  Traffic Inspection: View detailed packet information, including source/destination IPs, ports, and payload data.
  Statistics: Display summary statistics of the captured traffic (e.g., total packets, bytes sent/received).
  Live Monitoring: Continuously monitor and display new packets in a user-friendly interface.
  File Output: Save packet data to a file for later analysis.

Requirements

  Python 3.7+
    Libraries:
        scapy (for packet capturing and analysis)
        psutil (for network interface management)
        tkinter (for graphical user interface, optional)
        socket (for handling low-level network operations)

### GUIsniffer.py to run the program
