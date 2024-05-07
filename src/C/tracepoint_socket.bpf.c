#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include "socket_trace.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, struct write_info);
} write_data SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} write_events SEC(".maps");

//sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
/*
name: sys_enter_write
ID: 715
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:unsigned int fd;  offset:16;      size:8; signed:0;
        field:const char * buf; offset:24;      size:8; signed:0;
        field:size_t count;     offset:32;      size:8; signed:0;
*/
SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct syscall_enter_write_ctx* ctx)
{
  int pid = bpf_get_current_pid_tgid() >> 32;
  struct write_info data = {};
  data.common_pid = pid;
  data.syscall_nr = ctx->syscall_nr;
  data.fd = ctx->fd;
  data.count = ctx->count;
  bpf_map_update_elem(&write_data, &pid, &data, BPF_ANY);
  return 0;
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_write/format
/*
name: sys_exit_write
ID: 714
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret
*/
SEC("tracepoint/syscalls/sys_exit_write")
int sys_exit_write(struct syscall_exit_write_ctx* ctx)
{
  int pid = bpf_get_current_pid_tgid() >> 32;
  struct write_info *data;
  data = bpf_map_lookup_elem(&write_data, &pid);
  if(!data) {
    //loss enter info
    return 0;
  }
  bpf_map_delete_elem(&write_data, &pid);
  data->ret = ctx->ret;
  struct write_info *event;
  event = bpf_ringbuf_reserve(&write_events, sizeof(struct write_info), 0);
  if(!event) {
    return 0;
  }
  *event = *data;
  bpf_ringbuf_submit(event, 0);

  return 0;
}
