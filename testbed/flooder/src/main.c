// src/main.c

#include "connection.h"
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s [-m mode] [-d dest_ip] [-p port] [-s src_ip] [-r]\n\n"
            "Options:\n"
            "  -m mode      normal|syn   (default: normal)\n"
            "  -d dest_ip   target IP    (default: 127.0.0.1)\n"
            "  -p port      target port  (default: 8000)\n"
            "  -s src_ip    source IP    (default: 127.0.0.1)\n"
            "  -r           randomize src IP (overrides -s)\n",
            prog);
}

// Wait X seconds,
// show progress every 1 second.
static void wait(const unsigned int seconds) {
    unsigned int remaining = seconds;
    while (remaining > 0) {
        printf("[.] Waiting %u seconds...\n", remaining);
        fflush(stdout);
        sleep(1);
        remaining--;
    }
}

int main(int argc, char *argv[]) {
    const char *mode = "normal";
    const char *dest_ip = "127.0.0.1";
    const char *src_ip = "127.0.0.1";
    int port = 8000;
    bool random_src = false;
    int opt;

    while ((opt = getopt(argc, argv, "m:d:p:s:rh")) != -1) {
        switch (opt) {
        case 'm':
            mode = optarg;
            break;
        case 'd':
            dest_ip = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 's':
            src_ip = optarg;
            break;
        case 'r':
            random_src = true;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (strcmp(mode, "syn") == 0) {
        printf("[SYN mode] → %s:%d  (src: %s%s)\n", dest_ip, port,
               random_src ? "random" : src_ip, random_src ? "" : "");
        if (send_tcp_syn(dest_ip, port, src_ip, random_src) < 0) {
            fprintf(stderr, "[!] send_tcp_syn failed\n");
            return EXIT_FAILURE;
        }
        puts("[O] SYN sent.");
    } else {
        printf("[Normal mode] → %s:%d\n", dest_ip, port);
        int sockfd = connect_to_server(dest_ip, port);
        if (sockfd < 0) {
            fprintf(stderr, "[!] connect_to_server failed\n");
            return EXIT_FAILURE;
        }
        puts("[O] Connected. Sleeping 10s…");
        wait(10);
        close(sockfd);
        puts("[O] Connection closed.");
    }

    return EXIT_SUCCESS;
}
