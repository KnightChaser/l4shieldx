// xdpcollector/bpf/maps.c
#ifndef MAPS_H
#define MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/*
 * Traffic verdict constants (map indices)
 */
#define TRAFFIC_ALLOWED 0 /* Packet passed (no drop) */
#define TRAFFIC_DENIED 1  /* Packet dropped (blocked) */

/* =============================================================================
 * Map: blocked_ips
 * -----------------------------------------------------------------------------
 * A global hash of IPv4 source addresses that have exceeded the rate limit.
 *
 * Key:   __u32 (network‐order IPv4 address)
 * Value: __u8  (1 = blocked)
 *
 * Usage:
 *   - Populated by your XDP code when a source IP crosses the threshold.
 *   - Consulted at the top of the XDP hook to drop all subsequent packets.
 * =============================================================================
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
} blocked_ips SEC(".maps");

/* =============================================================================
 * Map: protected_ports
 * -----------------------------------------------------------------------------
 * Hash of TCP/UDP port numbers belonging to “protected” processes.
 * Only packets destined to these ports are counted/enforced.
 *
 * Key:   __u16 (host‐order port number)
 * Value: __u8  (1 = protected)
 *
 * Usage:
 *   - Updated by user‐space on “protect <PID>” or “unprotect <PID>”.
 *   - Checked first in XDP to skip all unprotected traffic.
 * =============================================================================
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(__u8));
} protected_ports SEC(".maps");

/* =============================================================================
 * Map: packet_count
 * -----------------------------------------------------------------------------
 * Per‐CPU counters for allowed vs. denied packets (for statistics/UI).
 *
 * Type:    PERCPU_ARRAY with two slots (TRAFFIC_ALLOWED, TRAFFIC_DENIED)
 * Key:     __u32 index (0 or 1)
 * =============================================================================
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} packet_count SEC(".maps");

/* =============================================================================
 * Map: packet_bytes
 * -----------------------------------------------------------------------------
 * Per‐CPU counters for allowed vs. denied bytes.
 *
 * Type:    PERCPU_ARRAY with two slots (TRAFFIC_ALLOWED, TRAFFIC_DENIED)
 * Key:     __u32 index (0 or 1)
 * Value:   __u64 per‐CPU byte count
 * =============================================================================
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} packet_bytes SEC(".maps");

/* =============================================================================
 * Map: events (ring buffer)
 * -----------------------------------------------------------------------------
 * Ring buffer used to emit packet events to user space.
 * Refer to events.h for the event structure.
 *
 * Entries: struct event_t
 * =============================================================================
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

/* =============================================================================
 * Map: ip_count_map
 * -----------------------------------------------------------------------------
 * Tracks per-source-IP packet counts (for thresholding).
 *
 * Key:   __u32 (network‐order IPv4 address)
 * Value: __u64 packet count within the current interval
 *
 * Usage:
 *   - Incremented in XDP for protected ports only.
 *   - Scanned and reset periodically by user‐space to enforce rate limit.
 * =============================================================================
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} ip_count_map SEC(".maps");

#endif /* MAPS_H */
