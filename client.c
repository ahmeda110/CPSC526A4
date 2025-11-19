// client_wait.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DEFAULT_PORT 34933
#define DEFAULT_DELAY 20
#define DEFAULT_MSG "REALDATA_FROM_CLIENT\n"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: ./client_wait <server_ip> [port] [delay_seconds] [message]\n");
        return 1;
    }

    char *server_ip = argv[1];
    int port = (argc >= 3) ? atoi(argv[2]) : DEFAULT_PORT;
    int delay = (argc >= 4) ? atoi(argv[3]) : DEFAULT_DELAY;
    char *msg = (argc >= 5) ? argv[4] : (char *)DEFAULT_MSG;

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

    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(s, (struct sockaddr *)&local, &len) == 0) {
        printf("Client source port: %d\n", ntohs(local.sin_port));
    }

    printf("Sleeping %d seconds before sending data...\n", delay);
    fflush(stdout);
    sleep(delay);

    ssize_t sent = send(s, msg, strlen(msg), 0);
    if (sent < 0) {
        perror("send");
        close(s);
        return 1;
    }

    printf("Client: sent %zd bytes\n", sent);
    close(s);
    return 0;
}
