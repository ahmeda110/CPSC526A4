#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: ./client_wait <server_ip> <port> <message> [delay_seconds]\n");
        return 1;
    }

    char *server_ip = argv[1];
    int port = atoi(argv[2]);
    char *msg = argv[3];

    int delay = 180; // default 60 seconds
    if (argc >= 5) {
        delay = atoi(argv[4]);
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

    printf("Sleeping %d seconds before sending data...\n", delay);
    fflush(stdout);
    sleep(delay);

    printf("Now press ENTER after you have run your attack...\n");
    fflush(stdout);
    getchar();  // wait so you have time to run ./attack R or D

    if (send(s, msg, strlen(msg), 0) < 0) {
        perror("send");
        close(s);
        return 1;
    }

    close(s);
    return 0;
}
