//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include "socket_trace.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

const volatile u16 listen_port = 0;
const char * SPAN_ID_KEY = "span-id: ";
const int SPAN_ID_KEY_LEN = 9;
const char * PARENT_SPAN_ID_KEY = "parent-span-id: ";
const int PARENT_SPAN_ID_KEY_LEN = 16;
const char * TRACE_ID = "trace-id: ";
const int TRACE_ID_LEN = 10;

const int ID_VALUE_LEN = 10; //64位十进制

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, struct data_args_t);
} read_args_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, pid_t);
  __type(value, struct request_info_t);
} request_info_map SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
  int pid = bpf_get_current_pid_tgid() >> 32;
  struct data_args_t *read_args;
  read_args = bpf_map_lookup_elem(&read_args_map, &pid);
  if(!read_args) {
    //loss enter info
    return 0;
  }
  __u64 count = 0;
  if(read_args->ret < ctx->ret) {
    count = ctx->ret;
  } else {
    count = read_args->ret;
  }

  if(!read_args->buf) {
    return 0;
  }
  char tmp_buffer[128] = {0};
  #define KEY_SIZE (sizeof(tmp_buffer) - 1)
  bpf_probe_read(tmp_buffer, count & KEY_SIZE, read_args->buf);
  for(int i = 0; i < 128; i++) {
    char c = tmp_buffer[i];
  }
  return 0;
}
