// xdpcollector/bpf/xdp_prog.c
#ifndef EVENT_H
#define EVENT_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Event structure for ring buffer
struct event_t {
    __u64 ts;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
} __attribute__((packed));

#endif /* EVENT_H */
