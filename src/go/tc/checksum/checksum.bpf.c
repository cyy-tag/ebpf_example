//go:build ignore
#include "../header/parser_header.h"
#include "../header/csum_helpers.h"
#include <bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// Session identifier
struct session_key {
	__u32 saddr; // IP source address
	__u32 daddr; // IP dest address
	__u16 sport; // Source port (set to 0 if ICMP)
	__u16 dport; // Dest port (set to 0 if ICMP)
	__u8 proto; // Protocol ID
};

// Session value
struct session_value {
	__u32 in_count; // Ingress packet count
	__u32 eg_count; // Egress packet count
};

#define MAX_MAP_ENTRIES 16

// Define an Hash map for storing packet Ingress and Egress count by 5-tuple session identifier
// User-space logic is responsible for cleaning the map, if potentially new entries needs to be monitored.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, struct session_key);
	__type(value, struct session_value);
} stats_map SEC(".maps");

// TC Ingress hook, to monitoring TCP/UDP/ICMP network connections and count packets.
SEC("tc")
int ingress_prog_func(struct __sk_buff *skb) {
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth;
	struct hdr_cursor nh = {.pos = data};
	int eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type != bpf_htons(ETH_P_IP))
		goto ingress_done;

	struct iphdr *iph;
	int ip_type = parse_ipv4hdr(&nh, data_end, &iph);
	if (ip_type != IPPROTO_TCP)
		goto ingress_done;
	struct tcphdr *tcph;
	if(parse_tcphdr(&nh, data_end, &tcph) < 0)
		goto ingress_done;

	if(bpf_ntohs(tcph->source) != 2333 &&
		bpf_ntohs(tcph->dest) != 2333) {
			goto ingress_done;
		}
	if(!is_http(&nh, data_end))
		goto ingress_done;
	bpf_printk("before ip checksum: %d tcp checksum: %d", iph->check, tcph->check);
	iph->check = cal_iph_csum(iph, data_end);
	tcph->check = cal_tcp_csum(iph, tcph, data_end);
	bpf_printk("after ip checksum: %d tcp checksum: %d", iph->check, tcph->check);
	iph->check = cal_iph_csum(iph, data_end);
	bpf_printk("process http");

ingress_done:

	return TC_ACT_OK;
}
