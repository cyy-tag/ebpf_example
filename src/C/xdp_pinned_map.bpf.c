#include <bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, struct datarec);
  __uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
  void *data_end = (void*)(long)ctx->data_end;
  void *data = (void*)(long)ctx->data;

  if (action >= XDP_ACTION_MAX)
    return XDP_ABORTED;
  
  struct datarec* rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
  if (!rec)
    return XDP_ABORTED;
  
  /* calculate packet length */
  __u64 bytes = data_end - data;
  //per cpu 不用加锁
  rec->rx_packets++;
  rec->rx_bytes += bytes;

  return action;
}

SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
  __u32 action = XDP_PASS;
  return xdp_stats_record_action(ctx, action);
}

SEC("xdp")
int xdp_drop_func(struct xdp_md *ctx)
{
  __u32 action = XDP_DROP;
  return xdp_stats_record_action(ctx, action);
}

SEC("xdp")
int xdp_abort_func(struct xdp_md *ctx)
{
  __u32 action = XDP_ABORTED;
  return xdp_stats_record_action(ctx, action);
}

