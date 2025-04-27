#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filter.h"

// eBPF 字节码
struct bpf_insn prog[] = {
  // 将字符串 "Hello, World!" 加载到栈中
  BPF_ST_MEM(BPF_DW, BPF_REG_10, -16, 0x6c6c6548), // "Hell"
  BPF_ST_MEM(BPF_DW, BPF_REG_10, -8,  0x6f57206f), // "o Wo"
  BPF_ST_MEM(BPF_B, BPF_REG_10, -1,  0x21),        // "rld!"

  // 设置 r1 = 栈地址（字符串的起始地址）
  BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
  BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -16),

  // 设置 r2 = 字符串长度（13）
  BPF_MOV64_IMM(BPF_REG_2, 13),

  // 调用 bpf_trace_printk
  BPF_EMIT_CALL(BPF_FUNC_trace_printk),

  // 返回 0
  BPF_MOV64_IMM(BPF_REG_0, 0),
  BPF_EXIT_INSN(),
};

// 字符串 "Hello, World!\n"
const char message[] = "Hello, World!\n";

// bpf 系统调用封装
int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

int main() {
  int prog_fd, map_fd;
  char log_buf[1024] = {0};
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
  attr.insns = (unsigned long)prog;
  attr.insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
  attr.license = (unsigned long)"GPL";
  attr.log_level = 1;
  attr.log_size = sizeof(log_buf);
  attr.log_buf = (unsigned long)log_buf;

  // 加载 eBPF 程序
  prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
  if (prog_fd < 0) {
      perror("BPF_PROG_LOAD");
      printf("Log: %s\n", log_buf);
      close(map_fd);
      return 1;
  }

  printf("eBPF program loaded with fd: %d\n", prog_fd);

  struct perf_event_attr e_attr = {
          .type = PERF_TYPE_TRACEPOINT,
          .size = sizeof(e_attr),
          .config = 737,
          .sample_period = 1,
          .sample_type = PERF_SAMPLE_RAW,
          .wakeup_events = 1,
      };

  int perf_fd = syscall(__NR_perf_event_open, &e_attr, -1, 0, -1, 0);

  if (perf_fd < 0) {
      perror("Failed to create perf event");
      return -1;
  }

  if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
      perror("Failed to enable perf event");
      close(perf_fd);
      return -1;
  }

  if (ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
      perror("Failed to attach eBPF program");
      close(perf_fd);
      return -1;
  }

  while(1) {
    sleep(1);
  }
  // 清理
  close(prog_fd);
  close(map_fd);
  return 0;
}
