// src/connection.h
#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Perform a full TCP connect (3-way handshake).
 * @param dest_ip  Target IPv4 address as a C-string.
 * @param port     Target TCP port.
 * @return socket fd on success, -1 on error.
 */
int connect_to_server(const char *dest_ip, int port);

/**
 * @brief Send one TCP SYN, spoofing the source IP.
 * @param dest_ip     Destination IPv4 address (string).
 * @param port        Destination TCP port.
 * @param src_ip      Source IPv4 address (string). Ignored if random_src==true.
 * @param random_src  If true, pick a random src-IP; otherwise use src_ip.
 * @return 0 on success, -1 on error.
 */
int send_tcp_syn(const char *dest_ip, // NOLINT
                 int port,            // NOLINT
                 const char *src_ip,  // NOLINT
                 bool random_src);

#endif /* CONNECTION_H */
