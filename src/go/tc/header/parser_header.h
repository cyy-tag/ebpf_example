#pragma once
#include "common.h"

#define ETH_ALEN 6

const int MAX_METHOD_LEN = 8;

struct hdr_cursor {
	void *pos;
  struct ethhdr *eth;
  struct iphdr *iph;
  struct tcphdr *tcph;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end)
{
  struct ethhdr *eth = nh->pos;

  if (nh->pos + ETH_HLEN > data_end)
    return -1;
  nh->pos += ETH_HLEN;
  nh->eth = eth;
  return eth->h_proto;
}

static __always_inline int parse_ipv4hdr(struct hdr_cursor *nh, void *data_end)
{
  struct iphdr *iph = nh->pos;
  if (nh->pos + sizeof(struct iphdr) > data_end)
    return -1;
  int hdrsize = iph->ihl * 4;
  /* check packet field is valid */
  if(hdrsize < sizeof(*iph))
    return -1;
  
  /* Variable-length IPv4 header, need to use byte-based arithmetic */
  if (nh->pos + hdrsize > data_end)
    return -1;

  nh->pos += hdrsize;
  nh->iph = iph;
  return iph->protocol;
}

static __always_inline int parse_tcphdr(struct hdr_cursor *nh, void *data_end)
{
  struct tcphdr *tcph = nh->pos;
  if (nh->pos + sizeof(struct tcphdr) > data_end)
    return -1;

  /* Variable-length TCP header */
  int hdrsize = tcph->doff * 4;
  /* check packet field is valid */
  if (hdrsize < sizeof(*tcph))
    return -1;
  
  if (nh->pos + hdrsize > data_end)
    return -1;
  nh->pos += hdrsize;
  nh->tcph = tcph;

  return 0;
}

static __always_inline int is_http(struct hdr_cursor *nh,  void * data_end) {
	void * data = nh->pos;
	if (nh->pos + MAX_METHOD_LEN > data_end) {
		return 0;
	}
	//clang-15
	if (__builtin_memcmp(data, "GET", 3) != 0 &&
			__builtin_memcmp(data, "POST", 4) != 0 &&
			__builtin_memcmp(data, "PUT", 3) != 0 &&
			__builtin_memcmp(data, "DELETE", 6) != 0 &&
			__builtin_memcmp(data, "HTTP", 4) != 0)
	{
			return 0;
	}
	return 1;
}
