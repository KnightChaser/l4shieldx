// src/main.c

#include "connection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    const char *mode = "normal";
    const char *ip = "127.0.0.1";
    int port = 8000;

    if (argc >= 2)
        mode = argv[1];
    if (argc >= 3)
        ip = argv[2];
    if (argc >= 4)
        port = atoi(argv[3]);

    if (strcmp(mode, "syn") == 0) {
        printf("[SYN mode] Sending TCP SYN to %s:%d\n", ip, port);
        if (send_tcp_syn(ip, port) < 0) {
            fprintf(stderr, "Failed to send SYN\n");
            return EXIT_FAILURE;
        }
        printf("SYN sent successfully.\n");
    } else {
        printf("[Normal mode] Connecting to %s:%d...\n", ip, port);
        int sockfd = connect_to_server(ip, port);
        if (sockfd < 0) {
            fprintf(stderr, "Failed to connect to server\n");
            return EXIT_FAILURE;
        }
        printf("Connected. Holding for 10 seconds...\n");
        sleep(10);
        close(sockfd);
        printf("Connection closed.\n");
    }
    return EXIT_SUCCESS;
}
