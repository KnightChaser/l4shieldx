// xdpcollector/bpf/xdp_prog.c
#include "event.h"
#include "maps.h"
#include "parser.h"

char LICENSE[] SEC("license") = "GPL";

/**
 * Modular helper to update per-CPU packet and byte counters
 *
 * @ctx: XDP context (data pointers, etc.)
 * @data_end: end of the packet data
 * @index: index of the CPU
 *
 */
static __always_inline void update_percpu_stats(struct xdp_md *ctx,
                                                void *data_end, __u32 index) {
    __u64 *packetCounter = bpf_map_lookup_elem(&packet_count, &index);
    if (packetCounter) {
        __sync_fetch_and_add(packetCounter, 1);
    }

    __u64 *byteCounter = bpf_map_lookup_elem(&packet_bytes, &index);
    if (byteCounter) {
        __u64 len = (void *)data_end - (void *)(long)ctx->data;
        __sync_fetch_and_add(byteCounter, len);
    }
}

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

    // Parse L2/L3/L4 and just issue XDP_PASS if parsing fails or non-TCP
    if (!parse_tcp(ctx, &data_end, &eth, &ip, &tcp)) {
        return XDP_PASS;
    }

    // Check if the source is blocked and update the statistics
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &ip->saddr);
    __u32 index = (blocked && *blocked) ? TRAFFIC_DENIED : TRAFFIC_ALLOWED;
    update_percpu_stats(ctx, data_end, index);

    if (index == TRAFFIC_DENIED) {
        // TODO: Delete bpf_prink() after testing
        bpf_printk("Blocked IP: %pI4\n", ip->saddr);
        return XDP_DROP;
    }

    // Update per-source-IP counter (network-order)
    {
        __u32 key = ip->saddr;
        __u64 *count = bpf_map_lookup_elem(&ip_count_map, &key);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            // Initialize the counter (into 1) if it doesn't exist
            __u64 init = 1;
            bpf_map_update_elem(&ip_count_map, &key, &init, BPF_ANY);
        }
    }

    // Emit event
    {
        struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->ts = bpf_ktime_get_ns();
            e->saddr = ip->saddr;
            e->daddr = bpf_ntohl(ip->daddr);
            e->sport = bpf_ntohs(tcp->source);
            e->dport = bpf_ntohs(tcp->dest);
            bpf_ringbuf_submit(e, 0);
        }
    }

    return XDP_PASS;
}
