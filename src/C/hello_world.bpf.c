#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(hello, const char *pathname)
{
  bpf_printk("hello world: %s\n", pathname);
  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
