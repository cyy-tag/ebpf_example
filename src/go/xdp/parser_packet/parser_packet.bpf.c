//go:build ignore
#include "../header/parser_header.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
  void *data = (void*)(long)ctx->data;
  void *data_end = (void*)(long)ctx->data_end;
  
  struct hdr_cursor nh = {.pos = data};
  __u32 action = XDP_PASS;
  
  if (parse_ethhdr(&nh, data_end) != bpf_htons(ETH_P_IP))
    return action;

  if (parse_ipv4hdr(&nh, data_end) !=IPPROTO_TCP)
    return action;
  
  if(parse_tcphdr(&nh, data_end) < 0)
    return action;

  bpf_printk("max_src: %llu, mac_dst: %llu, proto: %u\n",
            ether_addr_to_u64(nh.eth->h_source),
            ether_addr_to_u64(nh.eth->h_dest),
            bpf_ntohs(nh.eth->h_proto));
  //bpf_printk 最多有三个参数
  bpf_printk("ip_src: %x ip_dest: %x src_port: %u \n", 
              bpf_ntohl(nh.iph->saddr),
              bpf_ntohl(nh.iph->daddr),
              bpf_ntohs(nh.tcph->source));
  return action;
}
