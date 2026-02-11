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

using namespace std;

// ANSI Colors
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA  "\33[35m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"

pcap_t *handle;
ofstream logFile;

// Security Memory: Tracks which IP has hit which ports
map<string, set<int>> scanTracker;
const int SCAN_THRESHOLD = 10; 

void signal_handler(int signum) {
    cout << BOLD << RED << "\n[!] Shutting down IDS..." << RESET << endl;
    if (logFile.is_open()) logFile.close();
    pcap_breakloop(handle);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);

    if (ether_type == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + 14);
        int ip_header_len = ip_header->ip_hl * 4;

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);
            int tcp_header_len = tcp_header->th_off * 4;
            int d_port = ntohs(tcp_header->th_dport);

            // --- PORT SCAN DETECTION LOGIC ---
            scanTracker[src_ip].insert(d_port);
            if (scanTracker[src_ip].size() > SCAN_THRESHOLD) {
                cout << BOLD << RED << "\n[!!!] SECURITY ALERT: Port Scan Detected from " << src_ip << RESET << endl;
                logFile << "[ALERT] Port Scan Detected from " << src_ip << " hitting " << scanTracker[src_ip].size() << " ports." << endl;
            }

            cout << BLUE << "[TCP] " << RESET << src_ip << " -> " << dst_ip << ":" << CYAN << d_port << RESET << endl;
            logFile << "[TCP] " << src_ip << " -> " << dst_ip << ":" << d_port << endl;

            int total_headers_size = 14 + ip_header_len + tcp_header_len;
            const u_char *payload = packet + total_headers_size;
            int payload_len = pkthdr->len - total_headers_size;

            if (payload_len > 0) {
                cout << " | " << YELLOW << "Data: " << RESET;
                for (int i = 0; i < payload_len; i++) {
                    cout << (isprint(payload[i]) ? (char)payload[i] : '.');
                }
            }
            else if (ip_header->ip_p == IPPROTO_ICMP) {
            cout << GREEN << "[ICMP] " << RESET << src_ip << " -> " << dst_ip << " (Ping)" << endl;
            }
             else if (ip_header->ip_p == IPPROTO_UDP) {
             cout << YELLOW << "[UDP] " << RESET << src_ip << " -> " << dst_ip << endl;
            }
            cout << endl;
        }

      else if (ether_type == ETHERTYPE_ARP) {
        struct arphdr *arp_header = (struct arphdr *)(packet + 14);
        cout << BOLD << MAGENTA << "[ARP] " << RESET << "Hardware Type: " << ntohs(arp_header->ar_hrd) 
             << " | Protocol Type: " << ntohs(arp_header->ar_pro) << endl;
      }
        
        
    }
    logFile.flush(); 
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    vector<string> devList;

    pcap_findalldevs(&alldevs, errbuf);
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
