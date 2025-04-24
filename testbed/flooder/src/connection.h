// src/connection.h
#ifndef CONNECTION_H
#define CONNECTION_H

// Perform a full TCP connection (3-way handshake)
// and return the socket file descriptor in case of success.
int connect_to_server(const char *ip, int port);

// Send a single TCP SYN packet to the target (raw socket).
// Returns 0 on success.
int send_tcp_syn(const char *ip, int port);

#endif /* CONNECTION_H */
