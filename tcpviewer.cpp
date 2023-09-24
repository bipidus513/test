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

void print_MAC(uint8_t *addr){
    printf(" >> %02X:%02X:%02X:%02X:%02X:%02X\n",addr[0],addr[1],addr[2],addr[3],addr[4],addr[5]);
}

void print_IP(uint32_t ip){
    printf(" >> %d.%d.%d.%d\n", ip&0xff, (ip>>8)&0xff, (ip>>16)&0xff, (ip>>24)&0xff);    
}


int main(int argc, char* argv[]){
    //input Device
    if (argc != 2){
        usage();
        return -1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = argv[1];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;


    //Open live pcap session
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
    fprintf(stderr, "Failed to open device.. %s: %s\n",dev, errbuf);
    }else{
        printf("success to open pcap%s\n",dev);
    }

    //
    pcap_compile(handle, &fp, NULL, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
    }

    unsigned char * real_data;

    while(true){
//    struct pcap_pkthdr {
//      struct timeval ts;      / time stamp /
//      bpf_u_int32 caplen;  / length of portion present /
//      bpf_u_int32 len;       / length this packet (off wire) /
//    };
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

        printf("IP packet length : %d\n", ip_len);
        printf("IP header length : %d\n", ip_header_len);
        printf("TCP len : %d\n", tcp_header_len);
        printf("=================================\n");

        //print Ether Header
        printf("Dest MAC");
        print_MAC(packet->eth.ether_dhost);
        printf("Src MAC");
        print_MAC(packet->eth.ether_shost);
        printf("=================================\n");
        
        //print Ip Header
        printf("Dest IP");
        print_IP(packet->ip.iph_sourceip);
        printf("Src IP");
        print_IP(packet->ip.iph_destip);
        printf("=================================\n");

        //print TCP header
        printf("Dest port : %d\n", ntohs(packet->tcp.tcp_dport));
        printf("Src port : %d\n", ntohs(packet->tcp.tcp_sport));

        //print data
        if(ip_len-ip_header_len-tcp_header_len > 0){
            real_data = (unsigned char *)(packet + sizeof(ethheader) + ip_header_len + tcp_header_len);
            printf("data : \n");
            for(int i = 0; i < ip_len-ip_header_len-tcp_header_len; i++){
                printf("%02X ", real_data[i]);
                if(i%16 == 0){
                    printf("\n");
                }
            }
            printf("\n");
        }
        printf("=================================\n");

    }

    pcap_close(handle);
    return 0;
}
