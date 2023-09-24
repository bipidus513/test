#include <stdio.h>
#include <stdint.h>
/* Ethernet header */
struct ethheader {
    uint8_t  ether_dhost[6];    /* destination host address */
    uint8_t  ether_shost[6];    /* source host address */
    uint16_t ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP Header */
#pragma pack(push,1)
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_id; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  uint32_t           iph_sourceip; //Source IP address
  uint32_t           iph_destip;   //Destination IP address
};
#pragma pack(pop)

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

/* UDP Header */
struct udpheader
{
  uint16_t udp_sport;           /* source port */
  uint16_t udp_dport;           /* destination port */
  uint16_t udp_ulen;            /* udp length */
  uint16_t udp_sum;             /* udp checksum */
};

/* TCP Header */
struct tcpheader {
    uint16_t tcp_sport;               /* source port */
    uint16_t tcp_dport;               /* destination port */
    uint32_t   tcp_seq;                 /* sequence number */
    uint32_t   tcp_ack;                 /* acknowledgement number */
    uint8_t  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    uint8_t  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    uint16_t tcp_win;                 /* window */
    uint16_t tcp_sum;                 /* checksum */
    uint16_t tcp_urp;                 /* urgent pointer */
};

struct Packet {
    ethheader eth;
    ipheader ip;
    tcpheader tcp;
};
/* Psuedo TCP header */
struct pseudo_tcp
{
        unsigned saddr, daddr;
        unsigned char mbz;
        unsigned char ptcl;
        unsigned short tcpl;
        struct tcpheader tcp;
        char payload[1500];
};
