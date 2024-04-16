//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include <bpf_endian.h>

#define ETH_ALEN 6

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* to u64 in host order */
static inline __u64 ether_addr_to_u64(const __u8 *addr)
{
  __u64 u = 0;
  for(int i = ETH_ALEN - 1; i >= 0; i--)
    u = u << 8 | addr[i];
  return u;
}

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
  void *data = (void*)(long)ctx->data;
  void *data_end = (void*)(long)ctx->data_end;
  struct ethhdr *eth = data;
  __u64 offset = sizeof(*eth);

  if ((void*)eth + offset > data_end)
    return 0;
  bpf_printk("src: %llu, dst: %llu, proto: %u\n",
      ether_addr_to_u64(eth->h_source),
      ether_addr_to_u64(eth->h_dest),
      bpf_ntohs(eth->h_proto));
  return XDP_PASS;
}
