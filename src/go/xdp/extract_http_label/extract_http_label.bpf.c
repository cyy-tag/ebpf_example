//go:build ignore
#include "../header/parser_header.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_endian.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

const char * SPAN_ID_KEY = "span-id: ";
const int SPAN_ID_KEY_LEN = 9;
const char * PARENT_SPAN_ID_KEY = "parent-span-id: ";
const int PARENT_SPAN_ID_KEY_LEN = 16;
const char * TRACE_ID = "trace-id: ";
const int TRACE_ID_LEN = 10;
const int ID_VALUE_LEN = 10; //64位十进制

static __always_inline __u64 strtou64(const char *data, int len, void *data_end) {
  __u64 result = 0;
  for(int i = 0; i < len ; i++) {
    result *= 10;
    result += (int)(data[i] - '0');
  }
  return result;
}

static __always_inline int extract_trace_info_httpa(struct hdr_cursor *nh, void *data_end) {

  for(int index = 0; index < 200; index++) {
    if(nh->pos + index + SPAN_ID_KEY_LEN + ID_VALUE_LEN < data_end &&
        __builtin_memcmp(nh->pos+index, SPAN_ID_KEY, SPAN_ID_KEY_LEN)) {
      index += SPAN_ID_KEY_LEN;
      __u64 val = strtou64(nh->pos+index + SPAN_ID_KEY_LEN, ID_VALUE_LEN, data_end);
      index += ID_VALUE_LEN;
    }
  }
  return 0;
}

SEC("xdp")
int xdp_extract_http_label(struct xdp_md* ctx)
{
  void *data = (void*)(long)ctx->data;
  void *data_end = (void*)(long)ctx->data_end;

  struct hdr_cursor nh = {.pos = data};
  __u32 action = XDP_PASS;

  if (parse_ethhdr(&nh, data_end) != bpf_htons(ETH_P_IP))
    return action;
  
  if (parse_ipv4hdr(&nh, data_end) != IPPROTO_TCP)
    return action;
  
  if (parse_tcphdr(&nh, data_end) < 0)
    return action;
  
  if (is_http(&nh, data_end)) {
    //http protocol
    return action;
  }
  return action;
}
