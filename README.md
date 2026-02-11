# Network Traffic Analyzer

A high-performance, CLI-based Network Traffic Analyzer and Intrusion Detection System (IDS) built in C++ using the `libpcap` library. This project was developed as part of the B.Tech Computer Science curriculum to demonstrate deep-packet inspection and real-time security monitoring.

## 🚀 Features

* **Multi-Protocol Support:** Decodes Ethernet, IP, TCP, UDP, ICMP, and ARP packets.
* **Deep Packet Inspection (DPI):** Extracts and displays ASCII payloads from TCP streams.
* **Intelligent Security Alerts:** Real-time **Port Scan Detection** using `std::map` and `std::set` to track unique port hits per IP.
* **Dynamic Interface Selection:** Automatically detects available network cards (WiFi, Ethernet, Virtual) for high portability.
* **Professional CLI Visuals:** Color-coded output (ANSI) for easy differentiation of protocols and security alerts.
* **Data Persistence:** Real-time logging of all network activity to `network_log.txt`.



## 🛠️ Tech Stack

* **Language:** C++17
* **Library:** `libpcap` (Packet Capture library)
* **Environment:** Linux (Debian/Alpine/Kali)
* **Tools:** `g++`, `hping3` (for testing), `arping`

## 📋 Prerequisites

Before running the project, ensure you have the `libpcap` development headers installed:

```bash
# For Debian/Ubuntu
sudo apt-get update
sudo apt-get install libpcap-dev gdb
