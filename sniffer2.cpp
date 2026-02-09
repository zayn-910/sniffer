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

using namespace std;

// ANSI Color Codes for CLI "GUI" look
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"
#define BOLD    "\033[1m"

pcap_t *handle;
ofstream logFile;

void signal_handler(int signum) {
    cout << BOLD << RED << "\n[!] Stopping sniffer..." << RESET << endl;
    if (logFile.is_open()) logFile.close();
    pcap_breakloop(handle);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + 14);
        int ip_header_len = ip_header->ip_hl * 4;

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);
            int tcp_header_len = tcp_header->th_off * 4;
            
            cout << BLUE << "[TCP] " << RESET << src_ip << ":" << CYAN << ntohs(tcp_header->th_sport) 
                 << RESET << " -> " << dst_ip << ":" << CYAN << ntohs(tcp_header->th_dport) << RESET;

            int total_headers_size = 14 + ip_header_len + tcp_header_len;
            const u_char *payload = packet + total_headers_size;
            int payload_len = pkthdr->len - total_headers_size;

            if (payload_len > 0) {
                cout << " | " << YELLOW << "Data: " << RESET;
                for (int i = 0; i < payload_len; i++) {
                    cout << (isprint(payload[i]) ? (char)payload[i] : '.');
                }
            }
            cout << endl;
        } 
        else if (ip_header->ip_p == IPPROTO_ICMP) {
            cout << GREEN << "[ICMP] " << RESET << src_ip << " -> " << dst_ip << " (Ping)" << endl;
        }
        else if (ip_header->ip_p == IPPROTO_UDP) {
             cout << YELLOW << "[UDP] " << RESET << src_ip << " -> " << dst_ip << endl;
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    int i = 0, choice;
    vector<string> devList;

    // 1. Automatic Interface Discovery
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }

    cout << BOLD << CYAN << "--- Available Interfaces ---" << RESET << endl;
    for (d = alldevs; d != NULL; d = d->next) {
        cout << ++i << ". " << (d->name) << " (" << (d->description ? d->description : "No description") << ")" << endl;
        devList.push_back(d->name);
    }

    cout << "\nSelect interface number (1-" << i << "): ";
    cin >> choice;

    if (choice < 1 || choice > i) {
        cout << "Invalid choice." << endl;
        return 1;
    }

    string selectedDev = devList[choice - 1];

    // 2. Open Log File
    logFile.open("network_log.txt", ios::app);
    signal(SIGINT, signal_handler);

    // 3. Start Sniffing
    handle = pcap_open_live(selectedDev.c_str(), 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Error: " << errbuf << endl;
        return 2;
    }

    cout << BOLD << GREEN << "\n[!] Sniffer started on " << selectedDev << "..." << RESET << endl;
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_freealldevs(alldevs);
    return 0;
}
