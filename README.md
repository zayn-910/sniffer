# Network Traffic Analyzer

A high-performance, CLI-based Network Traffic Analyzer built in C++ using the `libpcap` library. This project demonstrate deep-packet inspection and real-time security monitoring.

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
```

## Compilation 
```bash
  g++ sniffer.cpp -o sniffer -lpcap
```

## 🚀 Usage Guide

1. Run the Analyzer
Packet capturing requires root privileges to access the network interface directly.

```bash
sudo ./sniffer
```


2. Select Your Interface
Upon launching, the program will list all available network interfaces (e.g., eth0, wlan0, enp0s8). Type the number corresponding to your target interface and press Enter.

3. Run the ping.sh
```bash
chmod +x ping.sh
./ping.sh
```

4. Monitoring & Logging

 * The analyzer will start printing live traffic in color-coded format.

 * All data is simultaneously appended to network_log.txt for later review.

 * Press Ctrl+C at any time to stop the capture and save the logs.




