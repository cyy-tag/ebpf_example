#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    struct event data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(&data.comm, sizeof(data.comm), name->name);
}