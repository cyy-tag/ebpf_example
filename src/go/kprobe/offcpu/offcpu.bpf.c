//go:build ignore
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK (1ULL << 8)
#endif // BPF_F_USER_STACK

char __license[] SEC("license") = "Dual MIT/GPL";

struct key_t {
    __u32 pid;
    __u32 tgid;
    int user_stack_id;
    int kernel_stack_id;
    char name[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, struct key_t);
  __type(value, __u64);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u64));
  __uint(max_entries, 10240); // all processes
} starts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, 100 * sizeof(__u64));
  __uint(max_entries, 10240);
} stacks SEC(".maps");

SEC("kprobe/finish_task_switch")
int oncpu(struct pt_regs *ctx) {
    __u32 pid, tgid;
    __u64 ts, *tsp;
    const char fmt_update[] = "update pid %u";
    const char fmt_read[] = "read pid %u";
    struct task_struct *prev = (struct task_struct* )(PT_REGS_PARM1_CORE(ctx));
    // bpf_core_read(&pid, 32, &prev->pid);
    // bpf_core_read(&tgid, 32, &prev->tgid);
    pid = BPF_CORE_READ(prev, pid);
    tgid = BPF_CORE_READ(prev, tgid);

    // const char *prev = (void *) PT_REGS_PARM1_CORE(ctx);
    // bpf_probe_read_kernel(&pid, sizeof(pid), (const void *)prev);
    // bpf_probe_read_kernel(&tgid, sizeof(tgid), (const void *)(prev + 4));
    // record previous thread sleep time
    ts = bpf_ktime_get_ns();
    bpf_trace_printk(fmt_update, sizeof(fmt_update), prev);
    bpf_map_update_elem(&starts, &pid, &ts, BPF_ANY);
    // get the current thread's start time
    pid = bpf_get_current_pid_tgid();
    tgid = bpf_get_current_pid_tgid() >> 32;
    tsp = bpf_map_lookup_elem(&starts, &pid);
    bpf_trace_printk(fmt_read, sizeof(fmt_read), pid);
    if (tsp == 0) {
      // bpf_trace_printk(fmt_str1, sizeof(fmt_str1), pid);
      return 0;        // missed start or filtered
    }

    // calculate current thread's delta time
    __u64 t_start = *tsp;
    __u64 t_end = bpf_ktime_get_ns();
    bpf_map_delete_elem(&starts, &pid);
    __u64 delta = t_end - t_start;
    // create map key
    struct key_t key = {};

    key.pid = pid;
    key.tgid = tgid;
    key.user_stack_id =  bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
    key.kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    bpf_get_current_comm(&key.name, sizeof(key.name));
    bpf_map_update_elem(&counts, &key, &delta, BPF_ANY);
    const char fmt_str2[] = "hello work222 %u";
    bpf_trace_printk(fmt_str2, sizeof(fmt_str2), pid);
    return 0;
}
