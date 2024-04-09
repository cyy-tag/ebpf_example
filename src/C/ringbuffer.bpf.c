//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(kprobe_execve, const char* filename, const char* argv, const char* envp)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    struct event *task_info;

    task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!task_info) {
        return 0;
    }

    task_info->pid = tgid;
    bpf_get_current_comm(&task_info->comm, 80);
    bpf_ringbuf_submit(task_info, 0);

    return 0;
}