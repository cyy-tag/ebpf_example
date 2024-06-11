//go:build ignore
#include "../header/parser_header.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include <bpf_endian.h>

//if_ether.h
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN		*/

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int vlan_tag_pop(struct hdr_cursor *nh, void *data_end, struct xdp_md *ctx)
{
  struct ethhdr eth_cpy;
  struct ethhdr *eth = nh->eth;
  struct vlan_hdr *vlh;
  __be16 h_proto = 0;
  int vlid;
  if(!proto_is_vlan(nh->eth->h_proto)) 
    return -1;

  vlh = (void *)(eth + 1);
  if((void *)vlh + sizeof(*vlh) > data_end)
    return -1;
  vlid = bpf_ntohs(vlh->h_vlan_TCI);
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));
  eth_cpy.h_proto = vlh->h_vlan_encapsulated_proto;

	/* Make a copy of the outer Ethernet header before we cut it off */
  /* Actually adjust the head pointer */
  if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
    return -1;
  
  /* Need to re-evaluate data *and* data_end and do new bounds checking
   *  after adjusting head
   */
  eth = (void*)(long)ctx->data;
  data_end = (void*)(long)ctx->data_end;
  if ((void *)eth + sizeof(*eth) > data_end)
    return -1;

  // // /* Copy back the old Ehternet header and update the proto type */
  __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

  return vlid;
}

SEC("xdp")
int xdp_pop_vlan(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  /* These keep track of the header type and iterator pointer */
  struct hdr_cursor nh = {.pos = data};
  int nh_type;

  if (proto_is_vlan(parse_ethhdr(&nh, data_end))) {
    vlan_tag_pop(&nh, data_end, ctx);
    bpf_printk("pop vlan tag \n");
  }

  return XDP_PASS;
}
