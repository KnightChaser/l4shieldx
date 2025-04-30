// xdpcollector/bpf/xdp_prog.c

#include "event.h"
#include "maps.h"
#include "parser.h"

char LICENSE[] SEC("license") = "GPL"; // SPDX license for BPF verifier

/**
 * xdp_tcp_hello - XDP program: count, filter, and report TCP packets
 * @ctx: XDP context (data pointers, etc.)
 *
 * 1. parse packet headers
 * 2. check block list map
 * 3. increment per-CPU counters
 * 4. drop if blocked, otherwise emit event into ring buffer
 *
 * returns XDP_DROP or XDP_PASS
 */
SEC("xdp")
int xdp_tcp_hello(struct xdp_md *ctx) {
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 index;

    if (!parse_tcp(ctx, &data_end, &eth, &ip, &tcp)) {
        // Not a valid TCP packet
        return XDP_PASS;
    }

    // Update the per-source-IP access counter for accounting
    __u32 key = ip->saddr;
    __u64 *packetCount = bpf_map_lookup_elem(&ip_count_map, &key);
    if (packetCount) {
        __sync_fetch_and_add(packetCount, 1);
    } else {
        // If the key doesn't exist, initialize it to 1
        __u64 inititalValue = 1;
        bpf_map_update_elem(&ip_count_map, &key, &inititalValue, BPF_ANY);
        packetCount = bpf_map_lookup_elem(&ip_count_map, &key);
    }

    if (packetCount) {
        bpf_printk("Packet count for IP %u: %llu\n", key, *packetCount);
    }

    // Enforce block list policy
    __u32 src = bpf_ntohl(ip->saddr);
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &src);

    index = (blocked && *blocked) ? TRAFFIC_DENIED : TRAFFIC_ALLOWED;

    // increment packet count for this index
    __u64 *pc = bpf_map_lookup_elem(&packet_count, &index);
    if (pc)
        __sync_fetch_and_add(pc, 1);

    // increment byte count for this index
    __u64 *pb = bpf_map_lookup_elem(&packet_bytes, &index);
    if (pb) {
        void *data = (void *)(long)ctx->data;
        __u64 len = (void *)data_end - data;
        __sync_fetch_and_add(pb, len);
    }

    // if blocked, drop and log
    if (index == TRAFFIC_DENIED) {
        bpf_printk("DROP %u\n", src);
        return XDP_DROP;
    }

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return XDP_PASS;
    }

    // populate event fields
    e->ts = bpf_ktime_get_ns();        // timestamp
    e->saddr = src;                    // source IP
    e->daddr = bpf_ntohl(ip->daddr);   // dest IP
    e->sport = bpf_ntohs(tcp->source); // source port
    e->dport = bpf_ntohs(tcp->dest);   // dest port

    // submit to userspace
    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}
