// xdpcollector/bpf/parser.h
#ifndef PARSER_H
#define PARSER_H

#include "if_ether.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/**
 * parse_tcp - parse L2/L3/L4 headers and ensure packet is TCP over IPv4
 * @ctx:   XDP context (contains data pointers)
 * @data_end: pointer to store packet end
 * @eth:   pointer to store Ethernet header pointer
 * @ip:    pointer to store IP header pointer
 * @tcp:   pointer to store TCP header pointer
 *
 * Returns true if packet is IPv4+TCP and all headers are within bounds.
 */
static __always_inline bool parse_tcp(struct xdp_md *ctx, void **data_end,
                                      struct ethhdr **eth, struct iphdr **ip,
                                      struct tcphdr **tcp) {
    // Load packet bounds
    void *data = (void *)(long)ctx->data;
    *data_end = (void *)(long)ctx->data_end;

    // L2: Ethernet
    *eth = (struct ethhdr *)data;
    if ((void *)(*eth + 1) > *data_end)
        return false;
    if (bpf_ntohs((*eth)->h_proto) != ETH_P_IP)
        return false;

    // L3: IPv4
    *ip = (struct iphdr *)(*eth + 1);
    if ((void *)(*ip + 1) > *data_end)
        return false;
    if ((*ip)->protocol != IPPROTO_TCP)
        return false;

    // L4: TCP
    *tcp = (void *)*ip + (*ip)->ihl * 4;
    if ((void *)(*tcp + 1) > *data_end)
        return false;

    return true;
}

#endif /* PARSER_H */
