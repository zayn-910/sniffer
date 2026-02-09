#include <iostream>                                                                                                     
#include <pcap.h>                                                                                                       
#include <signal.h>                                                                                                     
#include <netinet/in.h>                                                                                                 
#include <netinet/ip.h>                                                                                                 
#include <net/ethernet.h>                                                                                               
#include <arpa/inet.h>                                                                                                  
#include <netinet/tcp.h>                                                                                                
#include <netinet/udp. h>
using namespace std;                     

pcap_t *handle;                             

void signal_handler(int signum) {                                                                                               
    cout<<"\nStopping Sniffer...."<<endl;                                                                                   
    pcap_breakloop(handle);                                                                                         
}                                                                                                                                                                                                                                               


void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {                                     
    struct ether_header *eth_header = (struct ether_header *)packet;                                                                                                                                                                                
    
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {                                                                    
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));                                                                                                                                                                     
        char source_ip[INET_ADDRSTRLEN];                                                                                        
        char dest_ip[INET_ADDRSTRLEN];                                                                                          
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);                                                   
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);                       
        
        
        int ip_header_len = ip_header->ip_hl * 4;                                                                                                                                                                                                       
        if (ip_header->ip_p == IPPROTO_TCP) {                                                                                           
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);                    
            cout<<"[TCP] "<< source_ip << ":"<< ntohs(tcp_header->th_sport)<< "->" << dest_ip << ":" << ntohs(tcp_header->th_dport) <<endl;                                                                                                 
        }                                                                                                                                                                                                                                                                                                                                                                               
        else if (ip_header->ip_p == IPPROTO_UDP) {                                                                                      
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_len);                    
            cout<<"[UDP] "<< source_ip << ":"<< ntohs(udp_header->uh_sport)<< "->" << dest_ip << ":" << ntohs(udp_header->uh_dport) <<endl;                                                                                                 
        }                                                                                                                                                                                                                                                       
        else if (ip_header->ip_p == IPPROTO_ICMP){                                                                                      
            cout<< "[ICMP]" << source_ip << "-> "<< dest_ip << "(Ping Request/Reply)" <<endl;                       
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
