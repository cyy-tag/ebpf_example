//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include <bpf_endian.h>

#define ETH_ALEN 6
#define ETH_P_IP 0x0800

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct hdr_cursor {
	void *pos;
};

/* to u64 in host order */
static inline __u64 ether_addr_to_u64(const __u8 *addr)
{
  __u64 u = 0;
  for(int i = ETH_ALEN - 1; i >= 0; i--)
    u = u << 8 | addr[i];
  return u;
}

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                void *data_end,
                struct ethhdr **ethhdr)
{
  struct ethhdr *eth = nh->pos;
  int hdrsize = sizeof(*eth);

  if (nh->pos + hdrsize > data_end)
    return -1;
  nh->pos += hdrsize;
  *ethhdr = eth;

  return eth->h_proto;
}

static __always_inline int parse_ipv4hdr(struct hdr_cursor *nh,
                  void *data_end,
                  struct iphdr **iphdr)
{
  struct iphdr *iph = nh->pos;
  int hdrsize = sizeof(*iph);
  if (nh->pos + hdrsize > data_end)
    return -1;
  hdrsize = iph->ihl * 4;
  /* check packet field is valid */
  if(hdrsize < sizeof(*iph))
    return -1;
  
  /* Variable-length IPv4 header, need to use byte-based arithmetic */
  if (nh->pos + hdrsize > data_end)
    return -1;

  nh->pos += hdrsize;
  *iphdr = iph;

  return iph->protocol;
}

static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
                void *data_end,
                struct tcphdr **tcphdr)
{
  struct tcphdr *tcph = nh->pos;
  int hdrsize = sizeof(*tcph);
  if (nh->pos + hdrsize > data_end)
    return -1;

  /* Variable-length TCP header */
  hdrsize = tcph->doff * 4;
  /* check packet field is valid */
  if (hdrsize < sizeof(*tcph))
    return -1;
  
  if (nh->pos + hdrsize > data_end)
    return -1;
  nh->pos += hdrsize;
  *tcphdr = tcph;

  return 0;
}

// static __always_inline
// int parse_http(
//               struct hdr_cursor *nh,
//               void *payload,
//               void *data_end
//               )
// {

// }

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
  void *data = (void*)(long)ctx->data;
  void *data_end = (void*)(long)ctx->data_end;
  struct ethhdr *eth;

  __u32 action = XDP_PASS;
  
  struct hdr_cursor nh = {.pos = data};
  int eth_type = parse_ethhdr(&nh, data_end, &eth);

  if (eth_type != bpf_htons(ETH_P_IP))
    return action;

  struct iphdr *iph;
  int ip_type = parse_ipv4hdr(&nh, data_end, &iph);
  if (ip_type !=IPPROTO_TCP)
    return action;
  
  struct tcphdr *tcph;
  if(parse_tcphdr(&nh, data_end, &tcph) < 0)
    return action;

  bpf_printk("max_src: %llu, mac_dst: %llu, proto: %u\n",
            ether_addr_to_u64(eth->h_source),
            ether_addr_to_u64(eth->h_dest),
            bpf_ntohs(eth->h_proto));
  //bpf_printk 最多有三个参数
  bpf_printk("ip_src: %x ip_dest: %x src_port: %u \n", 
              bpf_ntohl(iph->saddr),
              bpf_ntohl(iph->daddr),
              bpf_ntohs(tcph->source));
  return action;
}
