// src/main.c

#include "connection.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    // Default IP and port
    const char *ip = "127.0.0.1";
    int port = 8000;
    int sockfd;

    if (argc >= 2) {
        ip = argv[1];
    }
    if (argc >= 3) {
        port = atoi(argv[2]);
    }

    printf("Connecting to %s:%d...\n", ip, port);
    sockfd = connect_to_server(ip, port);
    if (sockfd < 0) {
        fprintf(stderr, "Failed to connect to server\n");
        return EXIT_FAILURE;
    }

    // Wait for 10 seconds
    printf("Connected to server. Waiting for 10 seconds...\n");
    printf("Press Ctrl+C to exit.\n");
    sleep(10);

    printf("Connected successfully! Sockfd: %d\n", sockfd);
    close(sockfd);
    return EXIT_SUCCESS;
}
