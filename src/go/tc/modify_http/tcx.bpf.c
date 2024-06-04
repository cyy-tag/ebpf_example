//go:build ignore
#include "../header/parser_header.h"
#include "../header/csum_helpers.h"
#include <bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

const volatile u64 listen_port = 0;
//protocol head len + http first line
#define MAX_HTTP_HEAD 256
//14 + 60 + 60 + 122
char buffer[512];

const int label_max_len = 128;
char test_label[128] = "test-label: ";
const int test_label_len = 12;

static __always_inline int push_val(char* buffer, int start, __u64 val) {

	if(val == 0) {
		if(start + 2 < label_max_len) {
			__builtin_memcpy(buffer+start, "0\r\n", 3);
			return start + 3;
		} else {
			return -1;
		}
	}

	int i = start;
	#pragma unroll
	while(i < label_max_len && val > 0) {
		*(buffer + i) = (val %10) + '0';
		val /= 10;
		i++;
	}

	//revert
	int l = start, r = i - 1;
	#pragma unroll
	for(int l = start, r = i - 1; l < r; r--, l++) {
		char tmp = buffer[l];
		buffer[l] = buffer[r];
		buffer[r] = tmp;
	}

	if(i + 1 < label_max_len) {
		__builtin_memcpy(buffer+i, "\r\n", 2);
		return i + 2;
	} else {
		return -1;
	}
}

static __always_inline void process_http(struct hdr_cursor *nh, struct __sk_buff *skb) {
	void *data = nh->pos;
	void *data_end = (void *)(long)skb->data_end;

	int http_first_line_len = 0;
	//https://stackoverflow.com/questions/75643912/invalid-access-to-packet-while-iterating-over-packet-in-ebpf-program
	#pragma unroll
	for(int i = 0; i < MAX_HTTP_HEAD && data + i + 2 < data_end; i++) {
		if(__builtin_memcmp(data+i, "\r\n", 2) == 0) {
			//head line
			http_first_line_len = i+2;
			break;
		}
	}

	nh->pos += http_first_line_len;
	if(http_first_line_len > 0) {
		int extend_len = push_val(test_label, test_label_len, 2333);
		if(extend_len <= 0) {
			return;
		}
		//update l3 ip checksum
		add_ip_totlen(nh->iph, extend_len);
		//update l4 tcp checksum
		update_tcp_csum(nh->tcph, nh->iph);

		long head_off = (long)nh->pos - skb->data;
		//check bound
		if(head_off <= 0 || head_off > sizeof(buffer) || skb->data + head_off > (long)data_end)
			return;
		bpf_skb_load_bytes(skb, 0, buffer, head_off);

		//extend head size
		if(bpf_skb_change_head(skb, extend_len, 0)) {
			bpf_printk("change size error");
			return;
		}

		//assign head origin data
		bpf_skb_store_bytes(skb, 0, buffer, head_off, BPF_F_RECOMPUTE_CSUM);
		//push test label
		bpf_skb_store_bytes(skb, head_off, &test_label, extend_len, BPF_F_RECOMPUTE_CSUM);
	}

}

// TC Ingress hook, to monitoring TCP/UDP/ICMP network connections and count packets.
SEC("tc")
int ingress_prog_func(struct __sk_buff *skb) {
	// Return code corresponds to the PASS action in TC
	return TC_ACT_OK;
}

// TC Egress hook, same as Ingress but with IPs and Ports inverted in the key.
// This way, the connections match the same entry for the Ingress in the bpf map.
SEC("tc")
int egress_prog_func(struct __sk_buff *skb) {
	bpf_skb_pull_data(skb, skb->len);
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct hdr_cursor nh = {.pos = data};
	if (parse_ethhdr(&nh, data_end) != bpf_htons(ETH_P_IP))
		goto egress_done;

	if (parse_ipv4hdr(&nh, data_end) != IPPROTO_TCP)
		goto egress_done;
	
	if(parse_tcphdr(&nh, data_end) < 0)
		goto egress_done;

	if(bpf_ntohs(nh.tcph->source) != listen_port &&
		bpf_ntohs(nh.tcph->dest) != listen_port) {
			goto egress_done;
		}

	if(!is_http(&nh, data_end))
		goto egress_done;
	process_http(&nh, skb);
	bpf_printk("listen port %lld", listen_port);
egress_done:

	// Return code corresponds to the PASS action in TC
	return TC_ACT_OK;
}
