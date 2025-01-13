// file: user_program.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bpf.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#define BPF_MAP_TYPE_ARRAY 2

static int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(SYS_bpf, cmd, attr, size);
}

int main() {
  union bpf_attr attr;
  int prog_fd;


  // 加载 eBPF 程序
  memset(&attr, 0, sizeof(attr));
  attr.prog_type = BPF_PROG_TYPE_KPROBE;
  attr.insn_cnt = 0;
  attr.insns = 0;
  attr.license = (__u32)(unsigned long)"GPL";
  attr.log_level = 1;
  attr.log_size = 1024;
  attr.log_buf = 0;

  prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
  if (prog_fd < 0) {
      perror("BPF_PROG_LOAD");
      return 1;
  }

  // 读取 BPF 映射中的数据
  __u32 key = 0, value;
  if (bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) == 0) {
      printf("Value: %u\n", value);
  } else {
      perror("BPF_MAP_LOOKUP_ELEM");
  }

  close(prog_fd);
  return 0;
}
