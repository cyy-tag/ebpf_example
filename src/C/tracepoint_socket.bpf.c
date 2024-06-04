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
  __type(value, struct data_args_t);
} write_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, struct data_args_t);
} read_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, struct udp_args_t);
} sendto_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, struct udp_args_t);
} recvfrom_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} udp_events SEC(".maps");

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
// ssize_t write(int fd, const void buf[.count], size_t count);
SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct syscall_enter_write_ctx* ctx)
{
  //filter stdio 0-stdin 1-stdout 2-stderr
  if(ctx->fd < 3) {
    return 0;
  }
  int pid = bpf_get_current_pid_tgid() >> 32;
  struct data_args_t write_args = {};
  write_args.pid = pid;
  write_args.fd = ctx->fd;
  write_args.count = ctx->count;
  write_args.source_fn = SYSCALL_FUNC_WRITE;
  bpf_map_update_elem(&write_args_map, &pid, &write_args, BPF_ANY);
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
  struct data_args_t *write_args;
  write_args = bpf_map_lookup_elem(&write_args_map, &pid);
  if(!write_args) {
    //loss enter info
    return 0;
  }
  write_args->ret = ctx->ret;
  struct data_args_t *event;
  event = bpf_ringbuf_reserve(&events, sizeof(struct data_args_t), 0);
  if(!event) {
    bpf_map_delete_elem(&write_args_map, &pid);
    return 0;
  }
  *event = *write_args;
  bpf_map_delete_elem(&write_args_map, &pid);
  bpf_ringbuf_submit(event, 0);

  return 0;
}

/*
/sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
name: sys_enter_read
ID: 717
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:unsigned int fd;  offset:16;      size:8; signed:0;
        field:char * buf;       offset:24;      size:8; signed:0;
        field:size_t count;     offset:32;      size:8; signed:0;

print fmt: "fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->count))
*/
//ssize_t read(int fd, void buf[.count], size_t count);
SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct syscall_enter_read_ctx *ctx)
{
  struct data_args_t read_args = {};
  read_args.pid = bpf_get_current_pid_tgid() >> 32;
  read_args.fd = ctx->fd;
  read_args.count = ctx->count;
  read_args.source_fn = SYSCALL_FUNC_READ;
  bpf_map_update_elem(&read_args_map, &read_args.pid, &read_args, BPF_ANY);
  return 0;
}

/*
/sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format
name: sys_exit_read
ID: 716
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret
*/
SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct syscall_exit_read_ctx *ctx)
{
  int pid = bpf_get_current_pid_tgid() >> 32;
  struct data_args_t *read_args;
  read_args = bpf_map_lookup_elem(&read_args_map, &pid);
  if(!read_args) {
    //loss enter info
    return 0;
  }
  read_args->ret = ctx->ret;
  struct data_args_t *event;
  event = bpf_ringbuf_reserve(&events, sizeof(struct data_args_t), 0);
  if(!event) {
    bpf_map_delete_elem(&read_args_map, &pid);
    return 0;
  }
  *event = *read_args;
  bpf_map_delete_elem(&read_args_map, &pid);
  bpf_ringbuf_submit(event, 0);

  return 0;
}

/*
/sys/kernel/debug/tracing/events/syscalls/sys_enter_sendto/format
name: sys_enter_sendto
ID: 2290
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int fd;   offset:16;      size:8; signed:0;
        field:void * buff;      offset:24;      size:8; signed:0;
        field:size_t len;       offset:32;      size:8; signed:0;
        field:unsigned int flags;       offset:40;      size:8; signed:0;
        field:struct sockaddr * addr;   offset:48;      size:8; signed:0;
        field:int addr_len;     offset:56;      size:8; signed:0;

print fmt: "fd: 0x%08lx, buff: 0x%08lx, len: 0x%08lx, flags: 0x%08lx, addr: 0x%08lx, addr_len: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->buff)), ((unsigned long)(REC->len)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->addr)), ((unsigned long)(REC->addr_len))
*/
SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_enter_sendto(struct syscall_enter_sendto_ctx *ctx)
{
  struct udp_args_t sendto_args = {};
  sendto_args.source_fn = SYSCALL_FUNC_SENDTO;
  sendto_args.pid = bpf_get_current_pid_tgid() >> 32;
  sendto_args.fd = ctx->fd;
  sendto_args.count = ctx->len;
  sendto_args.flags = ctx->flags;
  // if(ctx->addr_len >= sizeof(struct sockaddr_in)) {
    // TODO: get dest addr and port
    // struct sockaddr_in * sa = (struct sockaddr_in *)(ctx->addr);
    // sendto_args.sa_family = BPF_CORE_READ(sa, sin_family);
    // sendto_args.sin_port = BPF_CORE_READ(sa, sin_port);
    // sendto_args.sin_addr = BPF_CORE_READ(sa, sin_addr.s_addr);
  // }
  bpf_map_update_elem(&sendto_args_map, &sendto_args.pid, &sendto_args, BPF_ANY);
  return 0;
}

/*
/sys/kernel/debug/tracing/events/syscalls/sys_exit_sendto/format
name: sys_exit_sendto
ID: 2289
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret
*/
SEC("tracepoint/syscalls/sys_exit_sendto")
int sys_exit_sendto(struct syscall_exit_sendto_ctx *ctx)
{
  int pid = bpf_get_current_pid_tgid() >> 32;
  struct udp_args_t *sendto_args_ptr=NULL;
  sendto_args_ptr = bpf_map_lookup_elem(&sendto_args_map, &pid);
  if(!sendto_args_ptr) {
    //loss enter info
    return 0;
  }
  sendto_args_ptr->ret = ctx->ret;
  struct udp_args_t *event;
  event = bpf_ringbuf_reserve(&udp_events, sizeof(struct udp_args_t), 0);
  if(!event) {
    bpf_map_delete_elem(&sendto_args_map, &pid);
    return 0;
  }
  *event = *sendto_args_ptr;
  bpf_map_delete_elem(&sendto_args_map, &pid);
  bpf_ringbuf_submit(event, 0);

  return 0;
}


/*
/sys/kernel/debug/tracing/events/syscalls/sys_enter_recvfrom/format
name: sys_enter_recvfrom
ID: 2288
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int fd;   offset:16;      size:8; signed:0;
        field:void * ubuf;      offset:24;      size:8; signed:0;
        field:size_t size;      offset:32;      size:8; signed:0;
        field:unsigned int flags;       offset:40;      size:8; signed:0;
        field:struct sockaddr * addr;   offset:48;      size:8; signed:0;
        field:int * addr_len;   offset:56;      size:8; signed:0;

print fmt: "fd: 0x%08lx, ubuf: 0x%08lx, size: 0x%08lx, flags: 0x%08lx, addr: 0x%08lx, addr_len: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->ubuf)), ((unsigned long)(REC->size)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->addr)), ((unsigned long)(REC->addr_len))
*/
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct syscall_enter_recvfrom_ctx *ctx)
{
  struct udp_args_t recvfrom_args = {};
  recvfrom_args.pid = bpf_get_current_pid_tgid() >> 32;
  recvfrom_args.fd = ctx->fd;
  recvfrom_args.flags = ctx->flags;
  recvfrom_args.count = ctx->size;
  recvfrom_args.source_fn = SYSCALL_FUNC_RECVFROM;
  bpf_map_update_elem(&recvfrom_args_map, &recvfrom_args.pid, &recvfrom_args, BPF_ANY);

  return 0;
}

/*
/sys/kernel/debug/tracing/events/syscalls/sys_exit_recvfrom/format
name: sys_exit_recvfrom
ID: 2287
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret
*/
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct syscall_exit_recvfrom_ctx *ctx)
{
  int pid = bpf_get_current_pid_tgid() >> 32;
  struct udp_args_t *recvfrom_args_ptr = NULL;
  recvfrom_args_ptr = bpf_map_lookup_elem(&recvfrom_args_map, &pid);
  if(!recvfrom_args_ptr) {
    //loss enter info
    return 0;
  }
  recvfrom_args_ptr->ret = ctx->ret;
  struct udp_args_t *event = NULL;
  event = bpf_ringbuf_reserve(&udp_events, sizeof(struct udp_args_t), 0);
  if(!event) {
    bpf_map_delete_elem(&recvfrom_args_map, &pid);
    return 0;
  }
  *event = *recvfrom_args_ptr;
  bpf_map_delete_elem(&recvfrom_args_map, &pid);
  bpf_ringbuf_submit(event, 0);

  return 0;
}
