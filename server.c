// server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    int port = 34933;              // 3 + last 4 digits of UCID
    if (argc == 2) {
        port = atoi(argv[1]);
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        exit(1);
    }

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(s);
        exit(1);
    }

    if (listen(s, 1) < 0) {
        perror("listen");
        close(s);
        exit(1);
    }

    printf("Server listening on port %d...\n", port);
    fflush(stdout);

    int client = accept(s, NULL, NULL);
    if (client < 0) {
        perror("accept");
        close(s);
        exit(1);
    }

    char buf[2048];
    int n;
    while ((n = recv(client, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = '\0';
        printf("Server received: %s\n", buf);
        fflush(stdout);
    }

    close(client);
    close(s);
    return 0;
}
