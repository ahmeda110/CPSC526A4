// client_wait.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: ./client_wait <server_ip> <port> <message>\n");
        return 1;
    }

    char *server_ip = argv[1];
    int port = atoi(argv[2]);
    char *msg = argv[3];

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    inet_pton(AF_INET, server_ip, &srv.sin_addr);

    if (connect(s, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        perror("connect");
        close(s);
        return 1;
    }
    printf("Client connected to %s:%d\n", server_ip, port);

    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(s, (struct sockaddr*)&local, &len) == 0) {
        printf("Client source port: %d\n", ntohs(local.sin_port));
    }

    fflush(stdout);

    // Optional small delay so handshake shows up clearly in pcap
    sleep(210);

    printf("Now perform your attack using this source port, then press ENTER to send data...\n");
    fflush(stdout);

    // Wait for ENTER
    getchar();

    send(s, msg, strlen(msg), 0);
    close(s);
    return 0;
}
