#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    int port = 34933;
    if (argc == 2) port = atoi(argv[1]);

    int s = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(s, (struct sockaddr*)&addr, sizeof(addr));
    listen(s, 1);

    printf("Server listening on port %d...\n", port);

    int client = accept(s, NULL, NULL);

    char buf[2048];
    int n;
    while ((n = recv(client, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = 0;
        printf("Server received: %s\n", buf);
    }

    close(client);
    close(s);
    return 0;
}
