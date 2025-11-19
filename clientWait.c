// client_wait.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: ./client_wait <server_ip> <message> [port]\n");
        return 1;
    }

    char *server_ip = argv[1];
    char *msg       = argv[2];
    int port        = 34933;   // default
    if (argc >= 4) {
        port = atoi(argv[3]);
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(port);
    if (inet_pton(AF_INET, server_ip, &srv.sin_addr) <= 0) {
        perror("inet_pton");
        close(s);
        return 1;
    }

    if (connect(s, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("connect");
        close(s);
        return 1;
    }

    printf("Client connected to %s:%d\n", server_ip, port);

    // Print local (source) port – needed for RST and inject
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(s, (struct sockaddr *)&local, &len) == 0) {
        int src_port = ntohs(local.sin_port);
        printf("Client source port: %d\n", src_port);
    }

    fflush(stdout);

    // Sleep to give you time to capture the handshake and run your attack
    printf("Client sleeping 20 seconds BEFORE sending data...\n");
    fflush(stdout);
    sleep(180);

    ssize_t sent = send(s, msg, strlen(msg), 0);
    if (sent < 0) {
        perror("send");
        close(s);
        return 1;
    }

    printf("Client: sent %zd bytes: \"%s\"\n", sent, msg);
    fflush(stdout);

    close(s);
    return 0;
}
