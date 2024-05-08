
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

//event data
struct data_args_t {
  enum syscall_src_func source_fn;
  int pid;
  unsigned int fd;
  size_t count;
  long ret;
};

//sendto args
struct udp_args_t {
  enum syscall_src_func source_fn;
  int pid;
  int fd;
  int flags;
  unsigned short int sa_family;
  uint16_t sin_port;
  uint32_t sin_addr;
  size_t count;
  size_t ret;
};


//https://stackoverflow.com/questions/76830721/bpf-tracepoint-args-and-why-theyre-different-in-different-example-code
//参数上可以选vmlinux的trace_event_raw_sys_enter 和 trace_event_raw_sys_exit
//或者自定义数据结构
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
struct syscall_enter_write_ctx {
  unsigned long long __pad0; //for ctx
  int syscall_nr;
  int __pad1; /*offset 12 size 4 */
  unsigned int fd;
  const char* buf;
  size_t count;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_write/format
struct syscall_exit_write_ctx {
  unsigned long long __pad0; //for ctx
  int syscall_nr;
  int __pad1;/*offset 12 size 4*/
  long ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
struct syscall_enter_read_ctx {
  unsigned long long __pad0; // for ctx
  int syscall_nr;
  int __pad1;/*offset 12 size 4*/
  unsigned int fd;
  char * buf;
  size_t count;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format
struct syscall_exit_read_ctx {
  unsigned long long __pad0; // for ctx
  int syscall_nr;
  int __pad1;/*offset 12 size 4*/
  long ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_sendto/format
struct syscall_enter_sendto_ctx {
  unsigned long long __pad0; // for ctx
  int syscall_nr;
  int __pad1;/*offset 12 size 4*/
  int fd;
  void* buf;
  size_t len;
  unsigned int flags;
  struct sockaddr *addr;
  int addr_len;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_sendto/format
struct syscall_exit_sendto_ctx {
  unsigned long long __pad0; // for ctx
  int syscall_nr;
  int __pad1;/*offset 12 size 4*/
  long ret;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_recvfrom/format
struct syscall_enter_recvfrom_ctx {
  unsigned long long __pad0; // for ctx
  int syscall_nr;
  int __pad1;/*offset 12 size 4*/
  int fd;
  void* ubuf;
  size_t size;
  unsigned int flags;
  struct sockaddr* addr;
  int* addr_len;
};

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_recvfrom/format
struct syscall_exit_recvfrom_ctx {
  unsigned long long __pad0; // for ctx
  int syscall_nr;
  int __pad1;/*offset 12 size 4*/
  long ret;
};
