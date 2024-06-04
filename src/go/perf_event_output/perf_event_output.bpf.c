//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct event {
  u32 pid;
  u8 comm[80];
};

/* BPF perbuf map */
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} pb SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));


SEC("kprobe/sys_execve")
int BPF_KPROBE(kprobe_execve, const char* filename, const char* argv, const char* envp)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    struct event task_info;

    task_info.pid = tgid;
    bpf_get_current_comm(&task_info.comm, 80);

    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &task_info, sizeof(task_info));
    return 0;
}
