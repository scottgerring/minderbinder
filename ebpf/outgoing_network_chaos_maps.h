//go:build ignore
#pragma once

#include "helpers.h"

/**
 * outgoing_network target
 */
struct outgoing_network_failure_config_t {
    // Nanoseconds to delay after the start of a process before injecting failures.
    // This is user-configured
    __u64 delay_after_start_ns;

    // A time in nanoseconds since boot before which we should not inject failures
    // This is derived from delay_after_start_ns when we discover new processes
    __u64 no_failures_before_ns;

    // The percentage 0-100 of calls to fail
    __u32 failure_rate_percent;

    __u32 target_is_active; // These will be filled linearly. Once we hit one that _isn't_
    // active, we're done.

} ;

struct outgoing_network_target_t {
    // The failure mode configuration
    struct outgoing_network_failure_config_t failure_config;
};

#define MAX_OUTGOING_NETWORK_ENTRIES 16
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_OUTGOING_NETWORK_ENTRIES);
    __type(key, char[TASK_COMM_LENGTH]); // comm
    __type(value, struct outgoing_network_target_t);
} outgoing_network_target_config SEC(".maps");

// Associate outgoing_network_config_config with PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);  // PID
    __type(value, struct outgoing_network_target_t); // Outgoing networ
} outgoing_network_targets SEC(".maps");
