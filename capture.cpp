#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string>
#include <stdlib.h>
#include "packet.h"


void print_IP(uint32_t ip){
    printf(" >> %d.%d.%d.%d\n", ip&0xff, (ip>>8)&0xff, (ip>>16)&0xff, (ip>>24)&0xff);    
}


int main(int argc, char* argv[]){
    
    char errbuf[PCAP_ERRBUF_SIZE];
    char* Pcap_interface = argv[1];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;


    //open_live를 사용하여 디바이스 열기
    handle = pcap_open_live(Pcap_interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
    fprintf(stderr, "Failed to open device.. %s: %s\n",Pcap_interface, errbuf);
    }else{
        printf("success open device %s wait a minute...\n",Pcap_interface);
    }

    pcap_compile(handle, &fp, NULL, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
    }

    unsigned char * real_data;

    while(true){
        struct pcap_pkthdr* header;
        const u_char* data;
        
        int res = pcap_next_ex(handle, &header, &data);
        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        Packet *packet = (Packet *)data;

        if(ntohs(packet->eth.ether_type) != 2048){
            continue;    
        }
        
        uint8_t ip_header_len = (packet->ip.iph_ihl & 0xf) * 4;
        uint8_t tcp_header_len = (packet->tcp.tcp_offx2 >> 4) * 4;

        uint16_t ip_len = ntohs(packet->ip.iph_len);

        if(packet->ip.iph_protocol != 6){
            continue;
        }
        printf("=================================\n");
        printf("IP packet length : %d\n", ip_len);
        printf("IP header length : %d\n", ip_header_len);
        printf("TCP len : %d\n", tcp_header_len);
        printf("\n");
        
        //print Ether Header
        printf("Ethernet Dst MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", packet->eth.ether_dhost[0], packet->eth.ether_dhost[1],
        packet->eth.ether_dhost[2], packet->eth.ether_dhost[3], packet->eth.ether_dhost[4], packet->eth.ether_dhost[5]);
        printf("Ethernet Src MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", packet->eth.ether_shost[0], packet->eth.ether_shost[1],
        packet->eth.ether_shost[2], packet->eth.ether_shost[3], packet->eth.ether_shost[4], packet->eth.ether_shost[5]);
        printf("\n");
        
        //print Ip Header
        printf("Dest IP : ");
        print_IP(packet->ip.iph_sourceip);
        printf("Src IP : ");
        print_IP(packet->ip.iph_destip);
        printf("\n");

        //print TCP header
        printf("Dest port : %d\n", ntohs(packet->tcp.tcp_dport));
        printf("Src port : %d\n", ntohs(packet->tcp.tcp_sport));

        
        printf("=================================\n");

    }

    pcap_close(handle);
    return 0;
}
