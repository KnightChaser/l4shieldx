// xdpcollector/bpf/xdp_prog.c
#ifndef MAPS_H
#define MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Counter indices */
#define TRAFFIC_ALLOWED 0
#define TRAFFIC_DENIED 1

/* IPv4 block list */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
} blocked_ips SEC(".maps");

/* per-CPU packet count */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} packet_count SEC(".maps");

/* per-CPU byte count */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} packet_bytes SEC(".maps");

/* ringbuf for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

/* per-source-IP access counter */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} ip_count_map SEC(".maps");

#endif /* MAPS_H */
