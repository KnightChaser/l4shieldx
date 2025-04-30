#include "event.h"
#include "maps.h"
#include "parser.h"

char LICENSE[] SEC("license") = "GPL"; // SPDX license for BPF verifier

/**
 * xdp_tcp_hello - XDP program: count, filter, and report TCP packets
 * @ctx: XDP context (data pointers, etc.)
 *
 * 1. parse packet headers
 * 2. check block list map and drop if blocked
 * 3. update per-source-IP counter
 * 4. increment per-CPU counters
 * 5. emit event into ring buffer
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

    // Parse L2/L3/L4 and just issue XDP_PASS if parsing fails or non-TCP
    if (!parse_tcp(ctx, &data_end, &eth, &ip, &tcp)) {
        return XDP_PASS;
    }

    // Enforce block list policy early (network-order key)
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &ip->saddr);
    if (blocked && *blocked) {
        bpf_printk("DROP blocked %pI4\n", &ip->saddr);
        return XDP_DROP;
    }

    // Update the per-source-IP access counter for accounting (network-order)
    __u32 key = ip->saddr;
    __u64 *packetCount = bpf_map_lookup_elem(&ip_count_map, &key);
    if (packetCount) {
        __sync_fetch_and_add(packetCount, 1);
    } else {
        __u64 initialValue = 1;
        bpf_map_update_elem(&ip_count_map, &key, &initialValue, BPF_ANY);
        packetCount = bpf_map_lookup_elem(&ip_count_map, &key);
    }
    if (packetCount) {
        bpf_printk("Packet count for IP %pI4: %llu\n", &ip->saddr,
                   *packetCount);
    }

    // Increment packet count and bytes(statistics) per-CPU
    index = TRAFFIC_ALLOWED;
    __u64 *pc = bpf_map_lookup_elem(&packet_count, &index);
    if (pc)
        __sync_fetch_and_add(pc, 1);

    __u64 *pb = bpf_map_lookup_elem(&packet_bytes, &index);
    if (pb) {
        void *data = (void *)(long)ctx->data;
        __u64 len = (void *)data_end - data;
        __sync_fetch_and_add(pb, len);
    }

    // Emit event
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->ts = bpf_ktime_get_ns();
        e->saddr = ip->saddr;
        e->daddr = bpf_ntohl(ip->daddr);
        e->sport = bpf_ntohs(tcp->source);
        e->dport = bpf_ntohs(tcp->dest);
        bpf_ringbuf_submit(e, 0);
    }

    return XDP_PASS;
}
