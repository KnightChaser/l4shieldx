// xdpcollector/bpf/xdp_prog.c
#include "event.h"
#include "maps.h"
#include "parser.h"

char LICENSE[] SEC("license") = "GPL";

/**
 * Modular helper to update per-CPU packet and byte counters
 * for XDP context.
 *
 * @ctx: XDP context (data pointers, etc.)
 * @data_end: end of the packet data
 * @index: index of the CPU
 *
 */
static __always_inline void
update_percpu_stats_xdp(struct xdp_md *ctx, void *data_end, __u32 index) {
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
 * Modular helper to update per-CPU packet and byte counters
 * for SKB context.
 *
 * @idx: index of the CPU
 * @pkt_len: length of the packet
 */
static __always_inline void update_percpu_stats_skb(__u32 idx, __u64 pkt_len) {
    __u64 *packetCounter = bpf_map_lookup_elem(&packet_count, &idx);
    if (packetCounter) {
        __sync_fetch_and_add(packetCounter, 1);
    }

    __u64 *byteCounter = bpf_map_lookup_elem(&packet_bytes, &idx);
    if (byteCounter) {
        __sync_fetch_and_add(byteCounter, pkt_len);
    }
}

/**
 * Modular helper to parse TCP packets from XDP context.
 *
 * @saddr: source address
 * @daddr: destination address
 * @tcp: TCP header
 * @idx: index of the CPU
 * @is_xdp: true if XDP context, false if SKB context
 * @ctx: XDP context
 * @data_end: end of the packet data
 * @skb_len: length of the packet
 */
static __always_inline int common_core(__u32 saddr, __u32 daddr,
                                       struct tcphdr *tcp, __u32 idx,
                                       bool is_xdp, struct xdp_md *ctx,
                                       void *data_end, __u64 skb_len) {
    if (idx == TRAFFIC_DENIED) {
        bpf_printk("Blocked IP: %pI4\n", &saddr);
        return is_xdp ? XDP_DROP : SK_DROP;
    }

    /* per-IP hit counter */
    __u64 one = 1, *ctr = bpf_map_lookup_elem(&ip_count_map, &saddr);
    if (ctr) {
        __sync_fetch_and_add(ctr, 1);
    } else {
        bpf_map_update_elem(&ip_count_map, &saddr, &one, BPF_ANY);
    }

    /* ringbuf event */
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->ts = bpf_ktime_get_ns();
        e->saddr = bpf_ntohl(saddr);
        e->daddr = bpf_ntohl(daddr);
        e->sport = bpf_ntohs(tcp->source);
        e->dport = bpf_ntohs(tcp->dest);
        bpf_ringbuf_submit(e, 0);
    }

    return is_xdp ? XDP_PASS : SK_PASS;
}

/**
 * XDP program to handle TCP packets.
 *
 * @ctx: XDP context (data pointers, etc.)
 *
 * Returns XDP_PASS or XDP_DROP based on the packet's source address.
 */
SEC("xdp")
int xdp_tcp_hello(struct xdp_md *ctx) {
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;

    /**
     * Parse and bounds-check L2/L3/L4.
     * If parsing fails(Not a TCP packet), just pass it up the stack.
     */
    if (!parse_xdp_tcp(ctx, &data_end, &eth, &ip, &tcp)) {
        return XDP_PASS;
    }

    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &saddr);
    __u32 idx = (blocked && *blocked) ? TRAFFIC_DENIED : TRAFFIC_ALLOWED;

    update_percpu_stats_xdp(ctx, data_end, idx);
    return common_core(saddr, daddr, tcp, idx, true, ctx, data_end, 0);
}

/**
 * SKB program to handle TCP packets.
 *
 * @skb: SKB context (data pointers, etc.)
 */
SEC("cgroup_skb/ingress")
int cgroup_tcp_hello(struct __sk_buff *skb) {
    void *data, *data_end;
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
    __u64 pkt_len;

    /*
     * Parse from SKB context.
     * If parsing fails(Not a TCP packet), just pass it up the stack.
     **/
    if (!parse_skb_tcp(skb, &data, &data_end, &eth, &ip, &tcp, &pkt_len)) {
        return SK_PASS;
    }

    __u32 saddr = bpf_ntohl(ip.saddr);
    __u32 daddr = bpf_ntohl(ip.daddr);
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &saddr);
    __u32 idx = (blocked && *blocked) ? TRAFFIC_DENIED : TRAFFIC_ALLOWED;

    update_percpu_stats_skb(idx, pkt_len);
    return common_core(saddr, daddr, &tcp, idx, false, NULL, data_end, pkt_len);
}
