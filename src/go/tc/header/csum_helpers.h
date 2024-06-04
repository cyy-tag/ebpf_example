#pragma once
#include "common.h"
#include <bpf_endian.h>

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_TOTL_OFF (ETH_HLEN + offsetof(struct iphdr, tot_len))

//Fold sum to 16 bit: add carrier to result
static __always_inline __u16 csum_fold_helper(__u64 csum) {
  #pragma unroll
  for(int i = 0; i < 4; i++) {
    if(csum >> 16) 
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

/* calculate ip header checksum */
/* https://en.wikipedia.org/wiki/Internet_checksum#Calculating_the_IPv4_header_checksum */
static __always_inline __u16 cal_iph_csum(struct iphdr* iph, void *data_end) {
  /* set check sum to 0*/
  iph->check = 0;
  __u8 hdrsize = iph->ihl * 4;
  void *data = (void *)iph;
  //https://docs.kernel.org/bpf/verifier.html#direct-packet-access
  //access ragne [data, data+DEFAULT_IP_HLEN], 后者变量需要是常数
  if(data + DEFAULT_IP_HLEN > data_end)
    return 0;
  __u64 csum = bpf_csum_diff(0, 0, data, DEFAULT_IP_HLEN, 0);

  //extend ip header size
  //动态长度访问，采用遍历方式
  #pragma unroll
  for(int i = 21; i <= 60 && i <= hdrsize && data + i + 1 < data_end; i += 2) {
    csum += *(unsigned short *)(data + i);
  }

  return csum_fold_helper(csum);
}

/* calculate tcp header checksum */
//https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_checksum_for_IPv4
static __always_inline __u16 cal_tcp_csum(struct iphdr* iph, struct tcphdr *tcph, void *data_end) {
  __u64 csum = 0;
  __u16 tcplen = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);

  //add the pseudo header
  //the source ip
  csum += (iph->saddr >> 16) & 0xFFFF;
  csum += (iph->saddr) & 0xFFFF;
  //the dest ip
  csum += (iph->daddr >> 16) & 0xFFFF;
  csum += (iph->daddr) & 0xFFFF;

  //protocol
  csum += bpf_htons(IPPROTO_TCP);
  //the length
  csum += bpf_htons(tcplen);

  tcph->check = 0;
  void * data = (void *)tcph;

  int i = 0;
  #pragma unroll
  for(; i < 1500 && data + i + 1 < data_end && tcplen > 0; i += 2) {
    csum += *(unsigned short *)(data + i);
    tcplen -= 2;
  }

  //if any bytes left, pad the bytes and add
  if(tcplen > 0 && data + i < data_end) {
    csum += *(__u8 *)(data + i);
  }
  return csum_fold_helper(csum);
}

static __always_inline __u16 csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len, __u8 proto) {
  __u64 csum = 0;
  csum = (__u64)saddr + (__u64)daddr + ((len + proto) << 8);
  return csum_fold_helper(csum);
}

static __always_inline void add_ip_totlen(struct iphdr *iph, int len) {
  __u16 old_len = iph->tot_len;
  __u16 new_len = bpf_htons(bpf_ntohs(old_len) + len);
  //使用bpf_skb_store_bytes和 bpf_l3_csum_replace 函数修改会破坏之前验证合法的指针，需要重新验证
  /*
  https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
  bpf_l3_csum_replace
  bpf_skb_store_bytes
  A call to this helper is susceptible to change the
                     underlying packet buffer. Therefore, at load time,
                     all checks on pointers previously done by the
                     verifier are invalidated and must be performed
                     again, if the helper is used in combination with
                     direct packet access.
  */
  iph->tot_len = new_len;
  __be32 old_val = old_len, new_val = new_len;
  __u64 csum = bpf_csum_diff(&old_val, sizeof(old_val), &new_val, sizeof(new_val), ~iph->check);
  iph->check = csum_fold_helper(csum);
}

static __always_inline void update_tcp_csum(struct tcphdr *tcph, struct iphdr* iph) {
	//tcph->check skb采用累加计算方式
	//https://elixir.bootlin.com/linux/v6.6.30/source/net/ipv4/tcp_ipv4.c#L641
	//初始化的值 /net/ipv4/tcp_ipv4.c __tcp_v4_send_check()
	/*
		th->check = ~tcp_v4_check(skb->len, saddr, daddr, 0);
	*/
  //这里的len为tcp头+payload长度, 不能使用bpf_change_tail后的skb->len
	tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, bpf_ntohs(iph->tot_len) - iph->ihl*4, IPPROTO_TCP);
  //tc->check到网卡层才加上tcpheader 和 payload
  //skb checksums offload include/linux/skbuff.h
}
