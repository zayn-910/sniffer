#include <iostream>                                                                                                     
#include <pcap.h>                                                                                                       
#include <signal.h>                                                                                                     
#include <netinet/in.h>                                                                                                 
#include <netinet/ip.h>                                                                                                 
#include <net/ethernet.h>                                                                                               
#include <arpa/inet.h>                                                                                                  
#include <netinet/tcp.h>                                                                                                
#include <netinet/udp. h>
#include <ctype.h>
using namespace std;                     

pcap_t *handle;                             

void signal_handler(int signum) {                                                                                               
    cout<<"\nStopping Sniffer...."<<endl;                                                                                   
    pcap_breakloop(handle);                                                                                         
}                                                                                                                                                                                                                                               


void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);
    int ip_header_len = ip_header->ip_hl * 4;

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_len);
        
        int tcp_header_len = tcp_header->th_off * 4;
        int total_headers_size = 14 + ip_header_len + tcp_header_len;

        const u_char *payload = packet + total_headers_size;
        int payload_len = pkthdr->len - total_headers_size;

        if (payload_len > 0) {
            std::cout << "Payload (" << payload_len << " bytes): ";
            for (int i = 0; i < payload_len; i++) {
                if (isprint(payload[i])) 
                    std::cout << payload[i];
                else 
                    cout << ".";
            }
            cout <<endl;
        }
    }
}                                                                                                                                                                                                                                               
int main() {                                                                                                                    
    char errbuf[PCAP_ERRBUF_SIZE];                                                                                          
    const char *dev="enp0s8";                                                                                                                                                                                                                       
    
    signal(SIGINT, signal_handler);                                                                                                                                                                                                                 
    handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);                                                                                                                                                                                           
    if (handle == NULL) {                                                                                                   
        cerr<<"Could not open device "<<dev<<":"<< errbuf <<endl;                                                               
        return 2;                                                                                                       
    }                                                                                                                                                                                                                                                       
    
    cout<<"Sniffing on "<<dev<<"...Press Ctrl+C to stop."<<endl;                                                                                                                                                                                    
    pcap_loop(handle, -1, packet_handler, NULL);                                                                                                                                                                                                    
    pcap_close(handle);                                                                                                     
    cout<<"Handle closed!!"<<endl;                                                                                          
    return 0;                                                                                                       
}
