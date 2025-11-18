#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: ./client_wait <server_ip> <port> <message>\n");
        return 1;
    }

    char *server_ip = argv[1];
    int port = atoi(argv[2]);
    char *msg = argv[3];

    int s = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in srv;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &srv.sin_addr);

    connect(s, (struct sockaddr*)&srv, sizeof(srv));
    printf("Client connected to %s:%d\n", server_ip, port);

    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    getsockname(s, (struct sockaddr*)&local, &len);

    printf("Client source port: %d\n", ntohs(local.sin_port));

    // -----------------------------
    // Print TCP seq + ack directly
    // -----------------------------
    struct tcp_info info;
    socklen_t info_len = sizeof(info);
    getsockopt(s, IPPROTO_TCP, TCP_INFO, &info, &info_len);

    printf("USE THESE VALUES FOR ATTACK:\n");
    printf("  client seq = %u\n", info.tcpi_unacked);
    printf("  client ack = %u\n", info.tcpi_snd_mss);

    printf("\nSleeping 12 seconds... Perform your attack now.\n");
    sleep(210);

    send(s, msg, strlen(msg), 0);
    close(s);
    return 0;
}
