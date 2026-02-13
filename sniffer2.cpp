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

// Globals for ncurses windows
WINDOW *header_win, *scroll_win, *alert_win;
pcap_t *handle;
ofstream logFile;
map<string, set<int>> scanTracker;
const int SCAN_THRESHOLD = 10;

void signal_handler(int signum) {
    endwin(); // Close ncurses
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

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);
            int d_port = ntohs(tcp_header->th_dport);

            scanTracker[src_ip].insert(d_port);
            if (scanTracker[src_ip].size() > SCAN_THRESHOLD) {
                wattron(alert_win, COLOR_PAIR(1) | A_BOLD);
                wprintw(alert_win, "[!] ALERT: Port Scan from %s (%lu ports)\n", src_ip, scanTracker[src_ip].size());
                wattroff(alert_win, COLOR_PAIR(1) | A_BOLD);
                wrefresh(alert_win);
            }

            wattron(scroll_win, COLOR_PAIR(2));
            wprintw(scroll_win, "[TCP] %s -> %s:%d\n", src_ip, dst_ip, d_port);
            wattroff(scroll_win, COLOR_PAIR(2));
        }
        else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + 14 + ip_header_len);
            int d_port = ntohs(udp_header->uh_dport);
            int s_port = ntohs(udp_header->uh_sport);

            wattron(scroll_win, COLOR_PAIR(3));
            wprintw(scroll_win, "[UDP] %s -> %s", src_ip, dst_ip);
            if(d_port == 53 || s_port == 53) wprintw(scroll_win, " [DNS]");
            if(d_port == 67 || d_port == 68) wprintw(scroll_win, " [DHCP]");
            wprintw(scroll_win, "\n");
            wattroff(scroll_win, COLOR_PAIR(3));
        }
    } 
    else if (ether_type == ETHERTYPE_ARP) {
        wattron(scroll_win, COLOR_PAIR(4));
        wprintw(scroll_win, "[ARP] Request/Reply Detected\n");
        wattroff(scroll_win, COLOR_PAIR(4));
    }

    wrefresh(scroll_win);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_findalldevs(&alldevs, errbuf);
    
    // --- Step 1: Standard Input (Before ncurses starts) ---
    vector<string> devList;
    int i = 0;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        cout << ++i << ". " << d->name << endl;
        devList.push_back(d->name);
    }
    int choice;
    cout << "Select Interface: "; cin >> choice;
    string selectedDev = devList[choice - 1];

    // --- Step 2: Initialize ncurses ---
    initscr();
    start_color();
    cbreak();
    noecho();
    
    // Color Pairs: 1:Red, 2:Blue, 3:Yellow, 4:Magenta, 5:Green
    init_pair(1, COLOR_RED, COLOR_BLACK);
    init_pair(2, COLOR_CYAN, COLOR_BLACK);
    init_pair(3, COLOR_YELLOW, COLOR_BLACK);
    init_pair(4, COLOR_MAGENTA, COLOR_BLACK);
    init_pair(5, COLOR_GREEN, COLOR_BLACK);

    header_win = newwin(3, COLS, 0, 0);
    scroll_win = newwin(LINES - 8, COLS, 3, 0);
    alert_win = newwin(5, COLS, LINES - 5, 0);

    scrollok(scroll_win, TRUE);
    scrollok(alert_win, TRUE);

    wattron(header_win, COLOR_PAIR(5) | A_BOLD);
    mvwprintw(header_win, 1, (COLS/2)-15, "SENTINEL IDS - NETWORK ANALYZER");
    wattroff(header_win, COLOR_PAIR(5) | A_BOLD);
    wrefresh(header_win);

    // --- Step 3: Start Capture ---
    logFile.open("network_log.txt", ios::app);
    signal(SIGINT, signal_handler);
    handle = pcap_open_live(selectedDev.c_str(), 65535, 1, 1000, errbuf);
    
    pcap_loop(handle, -1, packet_handler, NULL);

    endwin();
    return 0;
}
