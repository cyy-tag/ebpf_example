//go:build ignore
#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>
#include <bpf_endian.h>

//if_ether.h
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN		*/

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct hdr_cursor {
	void *pos;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
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

static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr eth_cpy;
  struct vlan_hdr *vlh;
  __be16 h_proto = 0;
  int vlid;

  if(!proto_is_vlan(eth->h_proto)) 
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
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  /* These keep track of the header type and iterator pointer */
  struct hdr_cursor nh = {.pos = data};
  int nh_type;

  struct ethhdr *eth;
  nh_type = parse_ethhdr(&nh, data_end, &eth);
  if (nh_type != -1 && proto_is_vlan(eth->h_proto)) {
    vlan_tag_pop(ctx, eth);
    bpf_printk("pop vlan tag \n");
  }

  return XDP_PASS;
}
