#include "helpers.h"
#include "syscall_chaos_maps.h"
#include "outgoing_network_chaos_maps.h"

// Per-cpu array to store execve data
// This is shared between probe/kretprobe _only_
struct new_process_t {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8 parent_comm[TASK_COMM_LENGTH];
    __u8 child_comm[TASK_COMM_LENGTH];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct new_process_t);
} execve_data SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_sys_execve(struct pt_regs *ctx) {

    __u32 map_id = 0;
    struct new_process_t* map_value = bpf_map_lookup_elem(&execve_data, &map_id);
    if (!map_value) {
        return 0;
    }

    // Get the easy bits
    map_value->pid = bpf_get_current_pid_tgid() >> 32;
	map_value->uid = bpf_get_current_uid_gid() & 0xffffffff;

    // Read the comm into it
    bpf_get_current_comm(&map_value->parent_comm, sizeof(map_value->parent_comm));

    return 0;
}

//
// Hook once we've completed launching a process. Here we check to see if the
// process launched matches anything we're targeting - either for system call
// chaos injection, _or_ for outgoing network chaos injection. It could be both!
//
// If we find a match, we then inject the downstream maps with the information
// they need to target the process we've discovered.
//
SEC("kretprobe/sys_ret_execve")
int kretprobe_sys_execve(struct pt_regs *ctx) {
    // Note the time the process started
    unsigned long long now = bpf_ktime_get_ns();
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u32 map_id = 0;
    struct new_process_t* map_value = bpf_map_lookup_elem(&execve_data, &map_id);
    if (!map_value) {
        return 0;
    }

    // Read the comm into it. First null out the string so we can use it
    // as a proper hash key
    for (int i = 0; i < TASK_COMM_LENGTH; i++) {
        map_value->child_comm[i] = 0;
    }
    bpf_get_current_comm(&map_value->child_comm, sizeof(map_value->child_comm));

    // 1. Do we have a system call target for this comm?
    struct syscall_failure_config_t* target_info = bpf_map_lookup_elem(&syscall_target_config, &map_value->child_comm);
    if (target_info) {
        // Log that we found a new PID to target, as well as the comm
        char fmt_str[] = "Found new process to target for syscall chaos: %d, comm=%s, not_before=%ul";
        bpf_trace_printk(fmt_str, sizeof(fmt_str), pid, map_value->child_comm);

        // Add it's configuration so we start targeting it
        struct syscall_failure_config_t target_config;
        target_config.syscall_id = target_info->syscall_id;
        target_config.no_failures_before_ns = now + target_info->delay_after_start_ns;
        bpf_map_update_elem(&syscall_targets, &pid, &target_config, BPF_ANY);
    }

    // 2. Do we have a outgoing network / TC target for this comm?
    struct outgoing_network_failure_config_t* net_target_info = bpf_map_lookup_elem(&outgoing_network_target_config, &map_value->child_comm);
    if (net_target_info) {
        // Log that we found a new PID to target, as well as the comm
        char fmt_str[] = "Found new process to target for outgoing_network chaos: %d, comm=%s, not_before=%ul";
        bpf_trace_printk(fmt_str, sizeof(fmt_str), pid, map_value->child_comm);

        // Add it's configuration so we start targeting it
        struct outgoing_network_target_t target_config;
        target_config.failure_config.failure_rate_percent = net_target_info->failure_rate_percent;
        target_config.failure_config.no_failures_before_ns = now + net_target_info->delay_after_start_ns;
        target_config.failure_config.target_is_active = 1;
        bpf_map_update_elem(&outgoing_network_targets, &pid, &target_config, BPF_ANY);
    }

    return 0;
}