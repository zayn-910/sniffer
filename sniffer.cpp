#include <iostream>
#include <fstream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <signal.h>
#include <ctype.h>
#include <vector>
#include <map>
#include <set>
#include <net/if_arp.h>
#include <iomanip>
#include <ctime>

using namespace std;

// ANSI Colors
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m" // Fixed escape sequence
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"

pcap_t *handle;
ofstream logFile;

map<string, set<int>> scanTracker;
const int SCAN_THRESHOLD = 10; 

string get_timestamp() {
    time_t now = time(0);
    char buf[80];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buf);
}

void signal_handler(int signum) {
    cout << BOLD << RED << "\n[!] Shutting down IDS..." << RESET << endl;
    if (logFile.is_open()) logFile.close();
    pcap_breakloop(handle);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);

    // --- 1. IP PROTOCOLS (TCP, UDP, ICMP) ---
    if (ether_type == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + 14);
        int ip_header_len = ip_header->ip_hl * 4;

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        // TCP LOGIC
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);
            int d_port = ntohs(tcp_header->th_dport);

            scanTracker[src_ip].insert(d_port);
            if (scanTracker[src_ip].size() > SCAN_THRESHOLD) {
                cout << BOLD << RED << "\n[!!!] SECURITY ALERT: Port Scan Detected from " << src_ip << RESET << endl;
                logFile << "[" << get_timestamp() << "] [ALERT] Port Scan Detected from " << src_ip << " hitting " << scanTracker[src_ip].size() << " ports." << endl;
            }

            cout << BLUE << "[TCP] " << RESET << src_ip << " -> " << dst_ip << ":" << CYAN << d_port << RESET << endl;
            logFile << "[" << get_timestamp() << "] [TCP] " << src_ip << " -> " << dst_ip << ":" << d_port << endl;
        } 
        // ICMP LOGIC
        else if (ip_header->ip_p == IPPROTO_ICMP) {
            cout << GREEN << "[ICMP] " << RESET << src_ip << " -> " << dst_ip << " (Ping)" << endl;
            logFile << "[" << get_timestamp() << "] [ICMP] " << src_ip << " -> " << dst_ip << " (Ping)" << endl;
        }
        // UDP LOGIC
        else if (ip_header->ip_p == IPPROTO_UDP) {
            cout << YELLOW << "[UDP] " << RESET << src_ip << " -> " << dst_ip << endl;
            logFile << "[" << get_timestamp() << "] [UDP] " << src_ip << " -> " << dst_ip << endl;
        }
    }
    // --- 2. ARP PROTOCOL ---
    else if (ether_type == ETHERTYPE_ARP) {
        const u_char *arp_ptr = packet + 14; 
        
        cout << BOLD << MAGENTA << "[ARP] " << RESET;
        logFile << "[" << get_timestamp() << "] [ARP] ";

        cout << "Sender MAC: ";
        logFile << "Sender MAC: ";
        for(int i=0; i<6; i++) {
            char mac_part[4];
            sprintf(mac_part, "%02x%c", arp_ptr[8+i], (i==5) ? ' ' : ':');
            cout << mac_part;
            logFile << mac_part;
        }

        cout << " | Target MAC: ";
        logFile << " | Target MAC: ";
        for(int i=0; i<6; i++) {
            char mac_part[4];
            sprintf(mac_part, "%02x%c", arp_ptr[18+i], (i==5) ? ' ' : ':');
            cout << mac_part;
            logFile << mac_part;
        }
        cout << endl;
        logFile << endl;
    }

    logFile.flush(); // Force write to file immediately
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    vector<string> devList;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices." << endl;
        return 1;
    }

    int i = 0;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        cout << ++i << ". " << d->name << endl;
        devList.push_back(d->name);
    }

    int choice;
    cout << "Select Interface: "; cin >> choice;
    string selectedDev = devList[choice - 1];

    logFile.open("network_log.txt", ios::app);
    signal(SIGINT, signal_handler);

    handle = pcap_open_live(selectedDev.c_str(), 65535, 1, 1000, errbuf);
    cout << BOLD << GREEN << "[!] IDS Brain Active on " << selectedDev << RESET << endl;
    
    pcap_loop(handle, -1, packet_handler, NULL);
    return 0;
}
