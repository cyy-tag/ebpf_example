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

struct write_info {
  int common_pid;
  int syscall_nr;
  unsigned int fd;
  size_t count;
  long ret;
};
