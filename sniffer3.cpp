#include <iostream>
#include <fstream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <signal.h>
#include <vector>
#include <map>
#include <set>
#include <ncurses.h>
#include <iomanip>

using namespace std;

// Globals for ncurses windows and pcap
WINDOW *header_win, *scroll_win, *alert_win;
pcap_t *handle;
ofstream logFile;

map<string, set<int>> scanTracker;
const int SCAN_THRESHOLD = 10;

void signal_handler(int signum) {
    endwin(); // Properly close ncurses mode
    if (logFile.is_open()) logFile.close();
    pcap_breakloop(handle);
    exit(0);
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

        // TCP LOGIC + Port Scan Detection
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);
            int d_port = ntohs(tcp_header->th_dport);

            scanTracker[src_ip].insert(d_port);
            if (scanTracker[src_ip].size() > SCAN_THRESHOLD) {
                wattron(alert_win, COLOR_PAIR(1) | A_BOLD);
                wprintw(alert_win, "[!] SECURITY ALERT: Port Scan from %s (%lu ports)\n", src_ip, scanTracker[src_ip].size());
                wattroff(alert_win, COLOR_PAIR(1) | A_BOLD);
                wrefresh(alert_win);
                logFile << "[ALERT] Port Scan from " << src_ip << " hitting " << scanTracker[src_ip].size() << " ports." << endl;
            }

            wattron(scroll_win, COLOR_PAIR(2));
            wprintw(scroll_win, "[TCP] %s -> %s:%d\n", src_ip, dst_ip, d_port);
            wattroff(scroll_win, COLOR_PAIR(2));
            logFile << "[TCP] " << src_ip << " -> " << dst_ip << ":" << d_port << endl;
        }
        // ICMP LOGIC
        else if (ip_header->ip_p == IPPROTO_ICMP) {
            wattron(scroll_win, COLOR_PAIR(5));
            wprintw(scroll_win, "[ICMP] %s -> %s (Ping)\n", src_ip, dst_ip);
            wattroff(scroll_win, COLOR_PAIR(5));
            logFile << "[ICMP] " << src_ip << " -> " << dst_ip << " (Ping)" << endl;
        }
        // UDP LOGIC
        else if (ip_header->ip_p == IPPROTO_UDP) {
            wattron(scroll_win, COLOR_PAIR(3));
            wprintw(scroll_win, "[UDP] %s -> %s\n", src_ip, dst_ip);
            wattroff(scroll_win, COLOR_PAIR(3));
            logFile << "[UDP] " << src_ip << " -> " << dst_ip << endl;
        }
    } 
    // ARP PROTOCOL
    else if (ether_type == ETHERTYPE_ARP) {
        wattron(scroll_win, COLOR_PAIR(4));
        wprintw(scroll_win, "[ARP] Frame Detected on Network\n");
        wattroff(scroll_win, COLOR_PAIR(4));
        logFile << "[ARP] Packet captured" << endl;
    }

    wrefresh(scroll_win);
    logFile.flush();
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    vector<string> devList;

    // 1. Initial Selection (Before ncurses takes over the screen)
    if (pcap_findalldevs(&alldevs, errbuf) == -1) return 1;
    int i = 0;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        cout << ++i << ". " << d->name << endl;
        devList.push_back(d->name);
    }
    int choice;
    cout << "Select Interface: "; cin >> choice;
    string selectedDev = devList[choice - 1];

    // 2. Initialize ncurses
    initscr();
    start_color();
    cbreak();
    noecho();

    // Setup Colors (1:Red, 2:Blue, 3:Yellow, 4:Magenta, 5:Green)
    init_pair(1, COLOR_RED, COLOR_BLACK);
    init_pair(2, COLOR_CYAN, COLOR_BLACK);
    init_pair(3, COLOR_YELLOW, COLOR_BLACK);
    init_pair(4, COLOR_MAGENTA, COLOR_BLACK);
    init_pair(5, COLOR_GREEN, COLOR_BLACK);

    // Create Windows (Height, Width, StartY, StartX)
    header_win = newwin(3, COLS, 0, 0);
    scroll_win = newwin(LINES - 8, COLS, 3, 0);
    alert_win = newwin(5, COLS, LINES - 5, 0);

    scrollok(scroll_win, TRUE); // Allow packets to scroll
    scrollok(alert_win, TRUE);  // Allow alerts to scroll

    // Draw Header
    wattron(header_win, COLOR_PAIR(5) | A_BOLD);
    box(header_win, 0, 0);
    mvwprintw(header_win, 1, (COLS/2)-12, "SENTINEL IDS - ACTIVE");
    wattroff(header_win, COLOR_PAIR(5) | A_BOLD);
    wrefresh(header_win);

    // 3. Start Capture
    logFile.open("network_log.txt", ios::app);
    signal(SIGINT, signal_handler);
    handle = pcap_open_live(selectedDev.c_str(), 65535, 1, 1000, errbuf);
    
    pcap_loop(handle, -1, packet_handler, NULL);

    endwin();
    return 0;
}
