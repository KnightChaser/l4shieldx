// xdpcollector/bpf/xdp_prog.c
#include "event.h"
#include "maps.h"
#include "parser.h"

#define DEFAULT_PACKET_THRESHOLD 1000 /* packets/sec */

char LICENSE[] SEC("license") = "GPL";

/**
 * Modular helper to update per-CPU packet and byte counters
 *
 * @ctx:      XDP context (data pointers, etc.)
 * @data_end: end of the packet data
 * @index:    index of the CPU
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
 * xdp_tcp_protect - XDP hook for port-based, per-PID DDoS protection
 *
 * @ctx: XDP context (data pointers, etc.)
 *
 * Steps:
 *   1. Parse L2/L3/L4; pass non-TCP/IPv4.
 *   2. Check if dest port is in protected_ports; if not, PASS.
 *   3. Lookup and increment per-IP counter; if > threshold, block.
 *   4. Update per-CPU stats and emit event.
 */
SEC("xdp")
int xdp_tcp_protect(struct xdp_md *ctx) {
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;

    /* 1) Parse and narrow to IPv4@TCP */
    if (!parse_xdp_tcp(ctx, &data_end, &eth, &ip, &tcp)) {
        return XDP_PASS;
    }

    /* 2) Check if the source is in the blocked list (early drop) */
    __u32 saddr = ip->saddr;
    __u8 *is_blocked = bpf_map_lookup_elem(&blocked_ips, &saddr);
    if (is_blocked && *is_blocked) {
        update_percpu_stats(ctx, data_end, TRAFFIC_DENIED);
        return XDP_DROP;
    }

    /* 3) Only protect configured ports */
    __u16 dport = bpf_ntohs(tcp->dest);
    __u8 *is_port = bpf_map_lookup_elem(&protected_ports, &dport);
    if (!is_port) {
        return XDP_PASS;
    }

    /* 4) Look up the threshold (XXX packets/sec (pps)) */
    __u64 packetThreshold = DEFAULT_PACKET_THRESHOLD;
    __u32 zero = 0;
    __u64 *pt = bpf_map_lookup_elem(&threshold_map, &zero);
    if (pt) {
        packetThreshold = *pt;
    } else {
        /* TODO: Delete bpf_printk() after debugging */
        bpf_printk("No threshold set, using default: %u\n", packetThreshold);
    }

    /* 5) Rate-limit by source IP */
    __u64 *packetCount = bpf_map_lookup_elem(&ip_count_map, &saddr);
    if (packetCount) {
        __u64 newCount = __sync_fetch_and_add(packetCount, 1) + 1;
        if (newCount > packetThreshold) {
            __u8 one = 1;
            bpf_map_update_elem(&blocked_ips, &saddr, &one, BPF_ANY);
            update_percpu_stats(ctx, data_end, TRAFFIC_DENIED);

            /* TODO: Delete bpf_printk() after debugging */
            bpf_printk("Blocked: %pI4 %pI4:%u\n", &saddr, &ip->daddr, dport);

            return XDP_DROP;
        }
    } else {
        /* The current source is reported first */
        __u64 init = 1;
        bpf_map_update_elem(&ip_count_map, &saddr, &init, BPF_ANY);
    }

    /*
     * 6) Update per-CPU stats and emit event
     *    If the packet reaches here, it means
     *    the packet is now allowed.
     */
    update_percpu_stats(ctx, data_end, TRAFFIC_ALLOWED);

    /* 5a) Emit event to the user space */
    struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->ts = bpf_ktime_get_ns();
        event->saddr = bpf_ntohl(saddr);
        event->daddr = bpf_ntohl(ip->daddr);
        event->sport = bpf_ntohs(tcp->source);
        event->dport = bpf_ntohs(tcp->dest);

        /* TODO: Delete bpf_printk() after debugging */
        bpf_printk("Allowed: %pI %u:%u\n", saddr, ip->daddr, dport);

        bpf_ringbuf_submit(event, 0);
    }

    return XDP_PASS;
}
