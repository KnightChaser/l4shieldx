// src/connection.c
#include "connection.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// (Utility) Generic checksum function
static unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned long sum = 0;
    for (; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    // fold 32-bit to 16-bit
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)(~sum);
}

// Pseudo-header for TCP checksum
struct pseudo_header {
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

int connect_to_server(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
        0) {
        perror("Connection failed");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int send_tcp_syn(const char *ip, int port) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("socket(SOCK_RAW)");
        return -1;
    }
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL)");
        close(sockfd);
        return -1;
    }

    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip_hdr = (struct iphdr *)packet;
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct sockaddr_in dest;

    // Destination address
    dest.sin_family = AF_INET;              // IPv4
    dest.sin_port = htons(port);            // destination port
    inet_pton(AF_INET, ip, &dest.sin_addr); // destination IP

    // Destination address
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, ip, &dest.sin_addr);

    // Randomize source IP and port
    uint16_t src_port = (rand() % (65535 - 1024)) + 1024; // ephemeral port
    uint32_t rand_ip = ((rand() & 0xFF) << 24) |          // 1st byte
                       ((rand() & 0xFF) << 16) |          // 2nd byte
                       ((rand() & 0xFF) << 8) |           // 3rd byte
                       (rand() & 0xFF);                   // 4th byte

    // IP header
    ip_hdr->ihl = 5;     // header length
    ip_hdr->version = 4; // IPv4
    ip_hdr->tos = 0;     // type of service
    ip_hdr->tot_len =
        htons(sizeof(struct iphdr) + sizeof(struct tcphdr)); // total length
    ip_hdr->id = htons(54321);
    ip_hdr->frag_off = 0;                 // fragment offset
    ip_hdr->ttl = 255;                    // time to live
    ip_hdr->protocol = IPPROTO_TCP;       // TCP
    ip_hdr->saddr = htonl(rand_ip);       // source IP (randomized)
    ip_hdr->daddr = dest.sin_addr.s_addr; // destination IP
    ip_hdr->check = 0;                    // checksum is calculated later
    ip_hdr->check =
        checksum(ip_hdr, sizeof(struct iphdr)); // calculate checksum

    // TCP header
    tcp_hdr->source = htons(src_port); // source port (randomized)
    tcp_hdr->dest = htons(port);       // destination port
    tcp_hdr->seq = htonl(0);           // sequence number
    tcp_hdr->ack_seq = 0;              // acknowledgment number
    tcp_hdr->doff = 5;                 // header size
    tcp_hdr->syn = 1;                  // SYN flag
    tcp_hdr->window = htons(5840);     // TCP window size
    tcp_hdr->check = 0;                // checksum is calculated later
    tcp_hdr->urg_ptr = 0;              // urgent pointer

    // Pseudo header + TCP header for checksum
    struct pseudo_header psh;
    psh.src_addr = inet_addr("127.0.0.1"); // TODO: use real source IP
    psh.dst_addr = dest.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    // Calculate TCP checksum
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp_hdr,
           sizeof(struct tcphdr));
    tcp_hdr->check = checksum(pseudogram, psize);
    free(pseudogram);

    // Send packet
    ssize_t sent = sendto(sockfd, packet, ntohs(ip_hdr->tot_len), 0,
                          (struct sockaddr *)&dest, sizeof(dest));
    if (sent < 0) {
        perror("sendto");
        close(sockfd);
        return -1;
    }
    close(sockfd);
    return 0;
}
