//go:build ignore
#pragma once

#include "outgoing_network_chaos_maps.h"
#include "helpers.h"
#include <linux/if_ether.h>


/**
 * Handlers for TC / outgoing connection breaking
 */

#define TC_ACT_UNSPEC -1   // Use default action configured by tc
#define TC_ACT_OK 0        // allow packet to procede
#define TC_ACT_SHOT 2      // drop the packet
#define TC_ACT_STOLEN 4	   // drop the packet but pretend it was succ

// Capture the creation of new sockets. If the process that creates the socket
// is one that we are interfering with the traffic of, we mark the socket with
// our magic number. This lets us pick up packets associated with the socket
// later on in the TC filter.
SEC("cgroup/sock_create")
int create_socket(struct bpf_sock* info) {

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // is this process in our targeted process map? If it is, mark
    __u32* val = bpf_map_lookup_elem(&outgoing_network_targets, &pid);
    if (!val || *val == 0) {
        return 1;
    }

    const char fmt_str[] = "sock_create pid=%d, dst_port=%d";
    bpf_trace_printk(fmt_str, sizeof(fmt_str), pid, info->dst_port);

    // Store the PID in the mark too, so we can find our configuration
    // later on in the TC filter
    info->mark = 123 ^ pid;

    return 1;
}

SEC("tc/filter_traffic")
int tc_filter_traffic(struct __sk_buff *skb) {

    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    // Drop out if we've not got a mark
    if (skb->mark == 0)
        return TC_ACT_OK;

    // If we xor out the mark, we can try to get configuration for the PID. That'll indicate
    // that we've got a process's socket to mess with, and let us get the configuration for it.
    __u64 pid = 123 ^ skb->mark;
    struct outgoing_network_target_t* val = bpf_map_lookup_elem(&outgoing_network_targets, &pid);
    if (!val) {
        return TC_ACT_OK;
    }

    // Bail out if we're not meant to touch it yet
    unsigned long long now = bpf_ktime_get_ns();
    if (now < val->failure_config.no_failures_before_ns) {
        return TC_ACT_OK;
    }
    // It's a socket we're targeting! Randomly drop some traffic
    __u32 rand = bpf_get_prandom_u32();

    // Drop rate read from userspace program
    if (rand % 100 <= val->failure_config.failure_rate_percent) {

        // Drop it
        return TC_ACT_STOLEN;
    }

    return TC_ACT_OK;
}