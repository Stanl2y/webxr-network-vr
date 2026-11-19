// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
//
// XDP program: emits one 32-byte record per IPv4 packet into a ring buffer
// and always returns XDP_PASS (observe-only, never alters traffic).
//
// Build (Linux, clang >= 14, libbpf headers):
//   clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu \
//         -c bpf/xdp.c -o bpf/xdp.o
//
// The record layout must match internal/record/record.go exactly:
//   off size field
//     0    8 ts_ns          bpf_ktime_get_ns()
//     8    4 flow_hash      FNV-1a over src|dst|sport|dport|proto
//    12    4 src_ip         network-order bytes
//    16    4 dst_ip         network-order bytes
//    20    2 src_port       host order
//    22    2 dst_port       host order
//    24    2 pkt_len        frame length
//    26    1 proto
//    27    1 dev            filled in by the userspace loader
//    28    1 queue          rx_queue_index
//    29    1 verdict        0 (XDP only sees forwarded ingress here)
//    30    2 sample_weight  1 (sampling happens in userspace)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct pkt_record {
	__u64 ts_ns;
	__u32 flow_hash;
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u16 pkt_len;
	__u8 proto;
	__u8 dev;
	__u8 queue;
	__u8 verdict;
	__u16 sample_weight;
};

_Static_assert(sizeof(struct pkt_record) == 32, "pkt_record must be 32 bytes");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); /* 4 MiB = 131072 records */
} events SEC(".maps");

#define FNV_OFFSET 2166136261u
#define FNV_PRIME 16777619u

static __always_inline __u32 fnv_byte(__u32 h, __u8 b)
{
	return (h ^ b) * FNV_PRIME;
}

static __always_inline __u32 fnv_u32_raw(__u32 h, __u32 v)
{
	/* bytes in memory order, matching Go's copy of [4]byte */
	const __u8 *p = (const __u8 *)&v;
	h = fnv_byte(h, p[0]);
	h = fnv_byte(h, p[1]);
	h = fnv_byte(h, p[2]);
	return fnv_byte(h, p[3]);
}

static __always_inline __u32 fnv_u16_le(__u32 h, __u16 v)
{
	h = fnv_byte(h, v & 0xff);
	return fnv_byte(h, v >> 8);
}

SEC("xdp")
int xdp_capture(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	__u32 ihl = ip->ihl * 4;
	if (ihl < sizeof(*ip))
		return XDP_PASS;

	__u16 sport = 0, dport = 0;
	void *l4 = (void *)ip + ihl;
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *th = l4;
		if ((void *)(th + 1) <= data_end) {
			sport = bpf_ntohs(th->source);
			dport = bpf_ntohs(th->dest);
		}
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *uh = l4;
		if ((void *)(uh + 1) <= data_end) {
			sport = bpf_ntohs(uh->source);
			dport = bpf_ntohs(uh->dest);
		}
	}

	struct pkt_record *r = bpf_ringbuf_reserve(&events, sizeof(*r), 0);
	if (!r)
		return XDP_PASS; /* ring full: userspace is behind, never block */

	__u32 h = FNV_OFFSET;
	h = fnv_u32_raw(h, ip->saddr);
	h = fnv_u32_raw(h, ip->daddr);
	h = fnv_u16_le(h, sport);
	h = fnv_u16_le(h, dport);
	h = fnv_byte(h, ip->protocol);

	__u64 len = data_end - data;
	r->ts_ns = bpf_ktime_get_ns();
	r->flow_hash = h;
	r->src_ip = ip->saddr;
	r->dst_ip = ip->daddr;
	r->src_port = sport;
	r->dst_port = dport;
	r->pkt_len = len > 0xffff ? 0xffff : (__u16)len;
	r->proto = ip->protocol;
	r->dev = 0;
	r->queue = (__u8)ctx->rx_queue_index;
	r->verdict = 0;
	r->sample_weight = 1;
	bpf_ringbuf_submit(r, 0);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
