// xdp_prog/xdp_prog.c
// go:build ignore
#include "if_ether.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// IPv4 block list
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
} blocked_ips SEC(".maps");

struct event_t {
    __u64 ts;    // BPF timestamp of the packet arrival
    __u32 saddr; // Source IP address
    __u32 daddr; // Destination IP address
    __u16 sport; // Source port
    __u16 dport; // Destination port
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); // 64K
} events SEC(".maps");

// Parse the packet and extract the fields (L2, L3, L4),
// and check if the packet is a TCP (Transmission Control Protocol) packet.
static __always_inline bool parse_tcp(struct xdp_md *ctx, void **data_end,
                                      struct ethhdr **eth, struct iphdr **ip,
                                      struct tcphdr **tcp) {
    void *data = (void *)(long)ctx->data;    // start of packet
    *data_end = (void *)(long)ctx->data_end; // end of packet

    // L2 (Ethernet)
    *eth = data;
    if ((void *)(*eth + 1) > *data_end) {
        return false;
    }
    if (bpf_ntohs((*eth)->h_proto) != ETH_P_IP) {
        return false;
    }

    // L3 (IP)
    *ip = (struct iphdr *)(*eth + 1);
    if ((void *)(*ip + 1) > *data_end) {
        return false;
    }
    if ((*ip)->protocol != IPPROTO_TCP) {
        return false;
    }

    // L4 (TCP)
    *tcp = (void *)*ip + (*ip)->ihl * 4;
    if ((void *)(*tcp + 1) > *data_end) {
        return false;
    }

    return true;
}

SEC("xdp")
int xdp_tcp_hello(struct xdp_md *ctx) {
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // If the packet is not a TCP packet, pass it to the next layer.
    if (!parse_tcp(ctx, &data_end, &eth, &ip, &tcp)) {
        return XDP_PASS;
    }

    // Check if the source IP address is in the block list.
    __u32 src = bpf_ntohl(ip->saddr);
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &src);
    if (blocked && *blocked) {
        // log to trace_pipe
        bpf_printk("DROP %u\n", src);
        // return XDP_DROP;  (Not dropping the packet for now!)
    }

    // Reserve space in the ring buffer for the event.
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return XDP_PASS;
    }

    e->ts = bpf_ktime_get_ns();
    e->saddr = bpf_ntohl(ip->saddr);
    e->daddr = bpf_ntohl(ip->daddr);
    e->sport = bpf_ntohs(tcp->source);
    e->dport = bpf_ntohs(tcp->dest);

    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}
