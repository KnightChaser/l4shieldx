// xdpcollector/bpf/xdp_prog.c
#ifndef MAPS_H
#define MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Counter indices for XDP vs SKB contexts */
#define TRAFFIC_ALLOWED 0
#define TRAFFIC_DENIED 1

/*
 * Blocklist of offending IPv4 addresses.
 * When an IP exceeds the rate limit in the cgroup-SKB program,
 * it's added here (value == 1), and XDP will DROP it immediately after.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
} blocked_ips SEC(".maps");

/*
 * Per-CPU packet count array for allowed/denied paths.
 * Used internally for statistics.
 *
 * packet_count: Number of packets arrived in the path, total
 * packet_bytes: Number of bytes arrived in packets in the path, total
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} packet_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} packet_bytes SEC(".maps");

/* Ring buffer for user-space events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

/*
 * Per-source-IP access counter
 * In the cgroup-SKB program, we increment this, and if it goes above
 * the threshold (e.g., 1,000 pps), we insert that source IP
 * into the blocklist(blocked_ips). immediately.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} ip_count_map SEC(".maps");

#endif /* MAPS_H */
