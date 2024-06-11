//go:build ignore
#include "../header/parser_header.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include <bpf_endian.h>

#define ETH_ALEN 6

char LICENSE[] SEC("license") = "Dual MIT/GPL";

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
