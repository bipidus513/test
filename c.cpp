#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string>
#include <stdlib.h>
#include "packet.h"


void usage(){
    printf("usage : tcpviewer <interface>\n");    
}


int main(int argc, char* argv[]){
    if (argc != 2){
        usage();
        return -1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = argv[1];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;


    //pcap_open_live를 이용하여 dev를 연다.
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
    fprintf(stderr, "Failed to open device.. %s: %s\n",dev, errbuf);
    }else{
        printf("success to open pcap %s\n",dev);
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
        
        uint8_t ip_header_len = (packet->ip.ip_hl & 0xf) * 4;
        uint8_t tcp_header_len = (packet->tcp.tcp_offx2 >> 4) * 4;

        uint16_t ip_len = ntohs(packet->ip.ip_len);

        if(packet->ip.ip_p != 6){
            continue;
        }

        printf("IP packet length : %d\n", ip_len);
        printf("IP header length : %d\n", ip_header_len);
        printf("TCP len : %d\n", tcp_header_len);
        printf("=================================\n");
        
        //MAC 주소 출력
        printf("Ethernet Dest MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", packet->eth.ether_dhost[0], packet->eth.ether_dhost[1],
        packet->eth.ether_dhost[2], packet->eth.ether_dhost[3], packet->eth.ether_dhost[4], packet->eth.ether_dhost[5]);
        printf("Ethernet Src MAC : %02X:%02X:%02X:%02X:%02X:%02X\n\n", packet->eth.ether_shost[0], packet->eth.ether_shost[1],
        packet->eth.ether_shost[2], packet->eth.ether_shost[3], packet->eth.ether_shost[4], packet->eth.ether_shost[5]);
        
        
        //IP 주소 출력
        printf("Dest IP : %d.%d.%d.%d\n", packet->ip.ip_dst[0],packet->ip.ip_dst[1],packet->ip.ip_dst[2],packet->ip.ip_dst[3]);
        printf("Src IP : %d.%d.%d.%d\n\n", packet->ip.ip_src[0],packet->ip.ip_src[1],packet->ip.ip_src[2],packet->ip.ip_src[3]");
        

        //print TCP header
        printf("Dest port : %d\n", ntohs(packet->tcp.tcp_dport));
        printf("Src port : %d\n", ntohs(packet->tcp.tcp_sport));

    }

    pcap_close(handle);
    return 0;
}
