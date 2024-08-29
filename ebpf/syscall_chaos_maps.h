#pragma once

/**
 * Process tracking
 */

// The failure configuration of a particular syscall.
// This needs to be bound back to a targeted process.
struct syscall_failure_config_t {
    // Nanoseconds to delay after the start of a process before injecting failures.
    // This is user-configured
    __u64 delay_after_start_ns;

    // A time in nanoseconds since boot before which we should not inject failures
    // This is derived from delay_after_start_ns when we discover new processes
    __u64 no_failures_before_ns;

    // The ID of the system call to inject failures for
    __u32 syscall_id;

    // The return code to inject. If it is -ve, flipping the sign around typically
    // gives the system call error code ID.
    __u32 injected_ret_code;

    // The percentage 0-100 of calls to fail
    __u32 failure_rate_percent;

};

struct syscall_target_t {
    // The failure mode configuration
    struct syscall_failure_config_t failure_config;

    __u32 target_is_active; // These will be filled linearly. Once we hit one that _isn't_
    // active, we're done.
};

// Syscall targets are loaded by user space to tell us which particular comms to mess with
#define MAX_SYSCALL_ENTRIES 16
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SYSCALL_ENTRIES);
    __type(key, char[TASK_COMM_LENGTH]); // comm
    __type(value, struct syscall_target_t);
} syscall_target_config SEC(".maps");

// A map for processes we should track. These are indexed
// by PID and have all the information needed to mess about
// with the syscalls.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);  // PID
    __type(value, struct syscall_failure_config_t); // Process info with PID and comm
} syscall_targets SEC(".maps");
