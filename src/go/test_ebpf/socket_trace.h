#pragma once

enum syscall_src_func {
	SYSCALL_FUNC_UNKNOWN,
	SYSCALL_FUNC_WRITE,
	SYSCALL_FUNC_READ,
	SYSCALL_FUNC_SEND,
	SYSCALL_FUNC_RECV,
	SYSCALL_FUNC_SENDTO,
	SYSCALL_FUNC_RECVFROM,
	// SYSCALL_FUNC_SENDMSG,
	// SYSCALL_FUNC_RECVMSG,
	// SYSCALL_FUNC_SENDMMSG,
	// SYSCALL_FUNC_RECVMMSG,
	// SYSCALL_FUNC_WRITEV,
	// SYSCALL_FUNC_READV,
	// SYSCALL_FUNC_SENDFILE
};

struct tcp_link_t {
	__u32 src_addr;
	__u32 dst_addr;
	__u16 src_port;
	__u16 dst_port;
	__u32 rcv_nxt;
	__u32 seq;
};

//event data
struct data_args_t {
  enum syscall_src_func source_fn;
  int pid;
  unsigned int fd;
  size_t count;
  long ret;
	const char * buf;
	struct tcp_link_t tcp_link;
};

struct trace_info_t {
  __u64 span_id;
  __u64 trace_id;
  __u64 parent_id;
  __u64 timestamp;
};

struct request_info_t {
  //network info
	struct tcp_link_t tcp_link;
  //treace info
  struct trace_info_t trace_info;
};

const volatile __u8 server_id;
/*0-前41位毫秒时间戳-8位server-id-*/
static __u64 get_uuid() {
	__u64 ms = bpf_ktime_get_ns() / 1000000;
	return ms;
};
