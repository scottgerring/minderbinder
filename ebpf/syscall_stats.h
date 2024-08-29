//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/**
 * Tracepoints - monitoring of error rates
 */

struct syscall_val_t {
    __u64 success;
    __u64 failure;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, int); // syscall number
    __type(value, struct syscall_val_t);
} syscall_counts SEC(".maps");

void update_syscall_count(int syscall_number, int success) {
    struct syscall_val_t *val, zero = {};

    // Lookup the key in the map
    val = bpf_map_lookup_elem(&syscall_counts, &syscall_number);
    if (!val) {
        // If key is not found, initialize the value
        val = &zero;
        bpf_map_update_elem(&syscall_counts, &syscall_number, val, BPF_NOEXIST);
        val = bpf_map_lookup_elem(&syscall_counts, &syscall_number);
        if (!val) {
            // If the key still cannot be found, return (should not happen)
            return;
        }
    }

    // Increment the appropriate counter
    if (success) {
        __sync_fetch_and_add(&val->success, 1);
    } else {
        __sync_fetch_and_add(&val->failure, 1);
    }
}

struct sys_exit_syscall_t {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_exit_execve")
int sys_exit_syscall(struct sys_exit_syscall_t* ctx) {
    long return_value = ctx->ret;

    if (return_value < 0) {
        const char fmt_str[] = "syscall [syscall_nr]=%d] failed with ret code=%l";
        bpf_trace_printk(fmt_str, sizeof(fmt_str), ctx->__syscall_nr, return_value);
    }

    update_syscall_count(ctx->__syscall_nr, return_value >= 0);

    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} context_switch_counts_t SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int sched_switch(void *ctx) {
    __u32 zero = 0;
    __u64 one = 1;
    __u64 *count = bpf_map_lookup_elem(&context_switch_counts_t, &zero);
    if (!count) {
        bpf_map_update_elem(&context_switch_counts_t, &zero, &one, BPF_ANY);
    } else {
        __sync_fetch_and_add(count, 1);
    }
    return 0;
}
