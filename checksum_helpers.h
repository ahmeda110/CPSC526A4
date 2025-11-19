// checksum_helpers.h (you can also just paste into each attack_*.c)
#ifndef CHECKSUM_HELPERS_H
#define CHECKSUM_HELPERS_H

#include <arpa/inet.h>

// TCP checksum (pseudo-header + TCP header + payload)
unsigned short csum_tcp(unsigned short *buf, int nwords) {
    unsigned long sum = 0;

    // IP source and dest (from IP header)
    sum += buf[6];
    sum += buf[7];
    sum += buf[8];
    sum += buf[9];

    sum += htons(6); // protocol = TCP
    // length of TCP header (20 bytes) + payload (nwords * 2)
    sum += htons(20 + (nwords << 1));

    // TCP header (20 bytes = 10 words) + payload (nwords words)
    for (int i = 10; i < 20 + nwords; ++i) {
        sum += buf[i];
    }

    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xffff);

    return (unsigned short)~sum;
}

// IP checksum (header only)
unsigned short csum_ip(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    while (nwords-- > 0) {
        sum += *buf++;
    }
    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xffff);
    return (unsigned short)~sum;
}

#endif
