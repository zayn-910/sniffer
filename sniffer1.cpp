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

using namespace std;

pcap_t *handle;
ofstream logFile;

// Function to handle Ctrl+C and close the sniffer gracefully
void signal_handler(int signum) {
    cout << "\n[!] Stopping sniffer and closing handle..." << endl;
    if (logFile.is_open()) {
        logFile.close();
    }
    pcap_breakloop(handle);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Check if it's an IP packet (EtherType 0x0800)
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + 14);
        int ip_header_len = ip_header->ip_hl * 4;

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        // Handle TCP Protocol
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);
            int tcp_header_len = tcp_header->th_off * 4;
            
            cout << "\n[TCP] " << src_ip << ":" << ntohs(tcp_header->th_sport) 
                 << " -> " << dst_ip << ":" << ntohs(tcp_header->th_dport);

            // File Logging
            logFile << "[TCP] " << src_ip << ":" << ntohs(tcp_header->th_sport) 
                    << " -> " << dst_ip << ":" << ntohs(tcp_header->th_dport);
            
            // Calculate payload offset and length
            int total_headers_size = 14 + ip_header_len + tcp_header_len;
            const u_char *payload = packet + total_headers_size;
            int payload_len = pkthdr->len - total_headers_size;

            if (payload_len > 0) {
                cout << " | Payload (" << payload_len << " bytes): ";
                for (int i = 0; i < payload_len; i++) {
                    if (isprint(payload[i])) cout << (char)payload[i];
                    else cout << ".";
                }
            }
            cout << endl;
        } 
        // Handle ICMP Protocol (Ping)
        else if (ip_header->ip_p == IPPROTO_ICMP) {
            cout << "[ICMP] " << src_ip << " -> " << dst_ip << " (Ping Request/Reply)" << endl;
            logFile << "[ICMP] " << src_ip << " -> " << dst_ip << " (Ping)" << endl;
        }
        // Handle UDP Protocol
        else if (ip_header->ip_p == IPPROTO_UDP) {
             cout << "[UDP] " << src_ip << " -> " << dst_ip << endl;
            logFile << "[UDP] " << src_ip << " -> " << dst_ip << endl;
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *dev = "enp0s8"; // Your Debian interface

    // Open log file in append mode (ios::app)
    logFile.open("network_log.txt", ios::app);
    if (!logFile.is_open()) {
        cerr << "Error: Could not open log file!" << endl;
        return 1;
    }

    signal(SIGINT, signal_handler);

    // Open interface in promiscuous mode
    handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "Error: " << errbuf << endl;
        return 2;
    }

    cout << "--- Professional Sniffer Active on " << dev << " ---" << endl;
    cout << "Press Ctrl+C to stop and view summary." << endl;
    
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    cout << "Capture Finished." << endl;
    return 0;
}
