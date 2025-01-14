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

static __always_inline void *get_socket_file_with_check(struct task_struct *task, int fd_num)
{
  void *file = NULL;
  struct fdtable *fdt_ptr = BPF_CORE_READ(task, files, fdt);
  if(!fdt_ptr || fd_num > BPF_CORE_READ(fdt_ptr, max_fds)) {
    return NULL;
  }
  bpf_probe_read_kernel(&file, sizeof(file), BPF_CORE_READ(fdt_ptr, fd) + fd_num);
  return file;
}

static __always_inline void *get_socket_from_fd(int fd_num)
{
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct file *file = get_socket_file_with_check(task, fd_num);
  if (!file) {
    return NULL;
  }
  void *private_data = NULL;
  bpf_core_read(&private_data, sizeof(private_data), &file->private_data);
  if(!private_data) {
    return NULL;
  }

  struct socket *socket = private_data;
  short socket_type = 0;
  //TODO: kernel 5.3 delete socket.wq void *check_file;
  void *sk;
  struct socket __socket = {};

  bpf_probe_read(&__socket, sizeof(__socket), (void *)socket);
  socket_type = __socket.type;
  if (__socket.file != file ) {
    sk = __socket.file;
    // check_file = __socket.wq;
  } else {
    //check_file = __socket.file;
    sk = __socket.sk;
  }

  if ( (socket_type == SOCK_STREAM || socket_type == SOCK_DGRAM) /*&& check_file == file */) {
    return sk;
  }

  return NULL;
}

static __always_inline int check_http(const char *data, __u64 count) {
  if(count < 8)
    return 0;
  //clang-15
	if (__builtin_memcmp(data, "GET", 3) != 0 &&
			__builtin_memcmp(data, "POST", 4) != 0 &&
			__builtin_memcmp(data, "PUT", 3) != 0 &&
			__builtin_memcmp(data, "DELETE", 6) != 0 &&
			__builtin_memcmp(data, "HTTP", 4) != 0)
	{
			return 0;
	}
	return 1;
}

static __always_inline __u64 strtou64(const char *data, int len) {
  __u64 result = 0;
  for(int i = 0; i < len ; i++) {
    result *= 10;
    result += (int)(data[i] - '0');
  }
  return result;
}

static __always_inline int extract_trace_info_http(const char *data, __u64 count, struct trace_info_t *trace_info) {
  int index = 0;
  int cnt = 0;

  while(index < count) {
    if(index + SPAN_ID_KEY_LEN + ID_VALUE_LEN < count &&
        __builtin_memcmp(data+index, SPAN_ID_KEY, SPAN_ID_KEY_LEN)) {
        index += SPAN_ID_KEY_LEN;
        strtou64(data+index + SPAN_ID_KEY_LEN, ID_VALUE_LEN);
        index += ID_VALUE_LEN;
        cnt++;
    }
    index++;
  }
  return cnt == 3 ? 1 : 0;
}

//sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
//ssize_t read(int fd, void buf[.count], size_t count);
SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
  int fd = ctx->args[0];
  if(fd < 3)
    return 0;
  /*tcp*/
  struct sock *sock = (struct sock*)get_socket_from_fd(fd);
  if(!sock || BPF_CORE_READ(sock, sk_protocol) != IPPROTO_TCP) {
    return 0;
  }
  const struct inet_sock *inet = (const struct inet_sock* )sock;
  __be32 dest = BPF_CORE_READ(inet, sk.__sk_common.skc_daddr);
  __be32 src = BPF_CORE_READ(inet, sk.__sk_common.skc_rcv_saddr);
  __be16 destp = BPF_CORE_READ(inet, sk.__sk_common.skc_dport);
  __be16 srcp = BPF_CORE_READ(inet, inet_sport);

  /*过滤条件*/
  if(bpf_ntohs(destp) != listen_port && \
    bpf_ntohs(srcp) != listen_port) {
      return 0;
    }
  
  struct data_args_t read_args = {};
  read_args.pid = bpf_get_current_pid_tgid() >> 32;
  read_args.fd = fd;
  read_args.buf = (const char *)ctx->args[1];
  read_args.count = (size_t)ctx->args[2];
  read_args.tcp_link.src_addr = bpf_ntohl(src);
  read_args.tcp_link.dst_addr = bpf_ntohl(dest);
  read_args.tcp_link.src_port = bpf_ntohs(srcp);
  read_args.tcp_link.dst_port = bpf_ntohs(destp);
  bpf_map_update_elem(&read_args_map, &read_args.pid, &read_args, BPF_ANY);
  return 0;
}

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
  pid = read_args->pid;
  if(check_http((const char *)read_args->buf, count), count) {
    char buffer[256] = {0};
    #define BUFFER_SIZE_MASK (sizeof(buffer) - 1)
    __u64 data_len = count & BUFFER_SIZE_MASK;
    bpf_probe_read(buffer, data_len, read_args->buf);
    // int index = 0;
    // while(index + SPAN_ID_KEY_LEN < data_len) {
    //   if(__builtin_memcmp(buffer + index, SPAN_ID_KEY, SPAN_ID_KEY_LEN) == 0 ) {
    //     // bpf_printk(" test %s", buffer);
    //   }
    //   ++index;
    // }
    // bpf_printk(" data %s", buffer);
    struct trace_info_t trace_info={.timestamp = bpf_ktime_get_ns()};
    if(extract_trace_info_http(buffer, data_len, &trace_info) == 0) {
      return 0;
    }
    struct request_info_t request_info={};
    bpf_map_update_elem(&request_info_map, &pid, &request_info, BPF_ANY);
  }
  return 0;
}
