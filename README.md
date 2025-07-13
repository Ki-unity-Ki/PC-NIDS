##**Network Intrusion Detection System (Python & C++)**

This project is a lightweight NIDS that detects and blackholes malicious IPs. Written in Python (Scapy) and C++ (libpcap), it’s suitable for Linux environments with iptables.

## Features

- Real-time packet sniffing
- Malicious IP threshold detection
- Automatic blackhole via `iptables`
- Optional dashboard UI

## Python Version

In bash:
- sudo python3 nids_blackhole.py

## C++ Version
- g++ -std=c++17 -lpcap -o nids_blackhole nids_blackhole.cpp
- sudo ./nids_blackhole

## Requirements
- Python: scapy
- C++: libpcap-dev, Linux with iptables

## Dashboard
- HTML/JavaScript UI provided in nids_dashboard.html (uses Server-Sent Events)

## Future Enhancements
- Signature-based attack detection
- Port scanning and DoS pattern alerts
- Cross-platform support (macOS/BSD)
- Logging and alert email system
