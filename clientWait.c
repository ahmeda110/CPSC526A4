#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

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
    printf("CLIENT SOURCE PORT = %d\n", ntohs(local.sin_port));

    printf("Waiting so you can run your attack...\n");
    fflush(stdout);

    // THIS IS CRITICAL
    sleep(120);     // enough time to run RST and INJECT attacks

    printf("Sending REALDATA now...\n");
    send(s, msg, strlen(msg), 0);

    close(s);
    return 0;
}
