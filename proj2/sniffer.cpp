#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <getopt.h>
#include <ctime>
#include <unistd.h>
#include <chrono>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>


#define BUFSIZE 50000

using namespace std;

pcap_t* handle;
bool arp = false, icmp4 = false, icmp6 = false, igmp = false, mld = false, ndp = false, tcp = false, udp = false;
int port;

void packet_output(const u_char *packet, int len) {
    int offset = 0;
    const int width = 16;
    const u_char *data;
    
    while (offset < len) {
        data = packet + offset;

        printf("0x%04x:", offset);

        for (int i = 0; i < width; ++i) {
            if (offset + i < len) {
                printf("%02x ", data[i]);
            } else {
                cout << "   ";
            }
        }

        for (int j = 0; j < width && offset + j < len; ++j) {
            if(j % 8 == 0 && j != 0) {
                cout << " ";
            }
            if(isprint(data[j])) {
                cout << data[j];
            }
            else {
                cout << ".";
            }
        }

        cout << '\n';
        offset += width;
    }
    cout << "\n\n";
}


string create_filter(string filter){
    string p;

    p = "port " + to_string(port);
    

    if(tcp){
        filter = "(tcp) and " + p;
    }

    if(udp) {
        if(filter.empty()) {
            filter = "(udp) and " + p;
        }
        else {
            filter += " or (udp) and " + p;
        }
    }
    
    if(arp) {
        if(filter.empty()) {
            filter = "(arp)";
        }
        else {
            filter += " or (arp)";
        }
    }

    if(icmp4) {
        if(filter.empty()) {
            filter = "(icmp)";
        }
        else {
            filter += " or (icmp)";
        }
    }

    if(icmp6) {
        if(filter.empty()) {
            filter = "(icmp6)";
        }
        else {
            filter += " or (icmp6)";
        }
    }

    if(igmp) {
        if(filter.empty()) {
            filter = "(igmp)";
        }
        else {
            filter += " or (igmp)";
        }
    }

    if(mld) {
        if(filter.empty()) {
            filter = "(icmp6 and icmp6[0] >= 130 and icmp6 and icmp6[0] <= 132)";
        }
        else {
            filter += " or (icmp6 and icmp6[0] >= 130 and icmp6 and icmp6[0] <= 132)";
        }
    }

    if(ndp) {
        if(filter.empty()) {
            filter = "(icmp6 and icmp6[0] >= 133 and icmp6 and icmp6[0] <= 137)";
        }
        else {
            filter += " or (icmp6 and icmp6[0] >= 133 and icmp6 and icmp6[0] <= 137)";
        }
    }

    return filter;
}

void packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet){
    
    const struct ether_header* eh = (const struct ether_header *)packet;
    const struct ip* ip = (const struct ip *)(packet + sizeof(struct ether_header));
    struct tcphdr* tcp = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip->ip_hl * 4));
    struct udphdr* udp = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip->ip_hl * 4));

    time_t current_time = time(nullptr);

    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", gmtime(&current_time));
    auto ms = chrono::duration_cast<chrono::milliseconds>(chrono::system_clock::now().time_since_epoch()).count() % 1000;
    cout << "timestamp: " << timestamp << "." << std::setfill('0') << std::setw(3) << ms << '\n';

    cout << "src MAC: ";
    for(int i = 0; i < 6; i++) {
        if(i != 5){
            printf("%02X:", eh->ether_shost[i]);
        }
        else {
            printf("%02X\n", eh->ether_shost[i]);
        }
    }

    cout << "dst MAC: ";
    for(int i = 0; i < 6; i++) {
        if(i != 5){
            printf("%02X:", eh->ether_dhost[i]);
        }
        else {
            printf("%02X\n", eh->ether_dhost[i]);
        }
    }
        
    cout << "frame length: " << ntohs(eh->ether_type) << " bytes\n";
    if(ntohs(eh->ether_type) == ETHERTYPE_IP) {
        char ipv4_src[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->ip_src), ipv4_src, INET_ADDRSTRLEN);
        cout << "src IP: " << ipv4_src << '\n';
        char ipv4_dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->ip_dst), ipv4_dst, INET_ADDRSTRLEN);
        cout << "dst IP: " << ipv4_dst << '\n';

        if(ip->ip_p == IPPROTO_TCP) {
            cout << "src port: " << htons(tcp->th_sport) << '\n';
            cout << "dst port: " << htons(tcp->th_dport) << '\n';
        }
        else if(ip->ip_p == IPPROTO_UDP) {
            cout << "src port: " << htons(udp->uh_sport) << '\n';
            cout << "dst port: " << htons(udp->uh_dport) << '\n';
        }
    }
    
    else if(ntohs(eh->ether_type) == ETHERTYPE_IPV6) {
        
        struct ip6_hdr* ipv6 = (struct ip6_hdr*) ip;
        char ipv6_src[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ipv6->ip6_src), ipv6_src, INET6_ADDRSTRLEN);
        cout << "src IP: " << ipv6_src << '\n';
        char ipv6_dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ipv6->ip6_dst), ipv6_dst, INET6_ADDRSTRLEN);
        cout << "dst IP: " << ipv6_dst << '\n';

        if(ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6) {
            cout << "src port: " << htons(tcp->th_sport) << '\n';
            cout << "dst port: " << htons(tcp->th_dport) << '\n';
        }
        if(ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 17) {
            cout << "src port: " << htons(udp->uh_sport) << '\n';
            cout << "dst port: " << htons(udp->uh_dport) << '\n';
        }
        
    }
    else{
        struct ether_arp * arp = (struct ether_arp*)(packet + sizeof(struct ether_header));
        char arp_src[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->arp_spa, arp_src, INET_ADDRSTRLEN);
        cout << "src IP: " << arp_src << '\n';
        char arp_dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, arp->arp_tpa, arp_dst, INET_ADDRSTRLEN);
        cout << "dst IP: " << arp_dst << '\n';
    }
    
    
    cout << '\n';
    packet_output(packet, header->len);

}

int main(int argc, char* argv[]) {

    string interface;
    string filter;
    int num = 1;
    char errbuf[PCAP_ERRBUF_SIZE];

     static struct option long_options[]{
        {"interface", required_argument, 0, 'i'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, 0, 1},
        {"icmp4", no_argument, 0, 2},
        {"icmp6", no_argument, 0, 3},
        {"igmp", no_argument, 0, 4},
        {"mld", no_argument, 0, 5},
        {"ndp", no_argument, 0, 6}
     };

    for(;;) {
        int opt = getopt_long(argc, argv, "i:p:tun:", long_options, NULL);
        if(opt == -1) {
            break;
        }
        switch(opt){
            case 'i':
                interface = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 't':
                tcp = true;
                break;
            case 'u':
                udp = true;
                break;
            case 'n':
                num = stoi(optarg);
                break;
            case 1:
                arp = true;
                break;
            case 2:
                icmp4 = true;
                break;
            case 3:
                icmp6 = true;
                break;
            case 4:
                igmp = true;
                break;
            case 5:
                mld = true;
                break;
            case 6:
                ndp = true;
                break;
            default:
                if(optopt == 'i' || optopt == 'n') {
                    continue;
                }
                else {
                    cerr << "Usage: ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n";
                    return 1;
                }
        }
    }
    
    if(interface.empty()){
        pcap_if_t* all_devices;
        if(pcap_findalldevs(&all_devices, errbuf) == -1){
            cerr << "Error in pcap_findalldevs()!\n" << errbuf << "\n";
            return 1;
        }
        pcap_if_t* dev = all_devices;
        cout << "List of all interfaces:\n";
        while(dev != NULL) {
            cout <<  dev->name << '\n';
            dev = dev->next;
        }   
        pcap_freealldevs(all_devices);
        return 1;
    }

    struct bpf_program bpf;
    bpf_u_int32 mask;            
	bpf_u_int32 ip_adress;
    
    
    if(pcap_lookupnet(interface.c_str(), &ip_adress, &mask, errbuf) == -1){
        cerr << "Error in pcap_lookupnet()!\n" << errbuf << "\n";
        return 1;
    }

    handle = pcap_open_live(interface.c_str(), BUFSIZE, 1, 1000, errbuf);
    if(handle == NULL) {
        cerr << "Error in pcap_open_live()!\n" << errbuf << "\n";
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        cerr << "Device must be Ethernet!\n" << errbuf << "\n";
        return 1;
    }

    filter = create_filter(filter);

    if (pcap_compile(handle, &bpf, filter.c_str(), 0, mask) == PCAP_ERROR) {
        cerr << "Error in pcap_compile()!\n";
        return 1;
    }

    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        cerr << "Error in pcap_setfilter()!\n";
        return 1;
    }
    
    if(pcap_loop(handle, num, packet_handler, nullptr) == PCAP_ERROR) {
        pcap_close(handle);
        cerr << "Error in pcap_loop()!\n";
        return 1;
    }
    pcap_close(handle);

    return 0;
}