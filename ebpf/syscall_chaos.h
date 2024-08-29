//go:build ignore
#pragma once

#include "syscall_chaos_maps.h"

#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

#include "helpers.h"

/**
 * Handler for all system calls, implementing the logic required to break them
 */
static __inline int handle_syscall(__u32 syscall_id, struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct syscall_failure_config_t *val = bpf_map_lookup_elem(&syscall_targets, &pid);
    if (!val) {
        return 0;
    }

    __u32 rand = bpf_get_prandom_u32();
    if (rand % 100 <= val->failure_rate_percent) {

        // Have we passed the cool-off period?
        unsigned long long now = bpf_ktime_get_ns();
        if (now > val->no_failures_before_ns) {
            char fmt_str[] = "Wrecking call with syscall ID=%d for PID=%d";
            bpf_trace_printk(fmt_str, sizeof(fmt_str), syscall_id, pid);

            // short-circuit the syscall - we're targeting this one
            // ret-code is the opposite of errno. This gets flipped around in glibc
            // e.g. an error number of '5' is indicated by returning -5
            bpf_override_return(ctx, val->injected_ret_code);
        } else {
            char fmt_str[] = "%llu < %llu";
            bpf_trace_printk(fmt_str, sizeof(fmt_str), now, val->no_failures_before_ns);
        }
    }

    return 0;
}

SEC("kprobe/any_syscall")

int kprobe_intercept_syscall(struct pt_regs *ctx) {
    // orig_rax stores the system call ID
    return handle_syscall(ctx->orig_rax, ctx);

}