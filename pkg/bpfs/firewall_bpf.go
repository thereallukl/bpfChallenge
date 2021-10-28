package bpfs

func GetCompilationFlagsFirewall() []string {
	return []string{"-w", "-I/usr/include", "-I/usr/include/linux", "-I/usr/include/x86_64-linux-gnu"}
}

const SourceFirewall string = `
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define BCC_LICENSE GPL

//BPF_TABLE("array", int, long, dropcnt, 256);]
BPF_TABLE("hash", unsigned int, int, block_ips, sizeof(unsigned int));
//BPF_ARRAY(block_ips, unsigned int, sizeof(unsigned int));

static inline struct iphdr* get_src_ip(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return 0;
    return bpf_ntohl(iph->saddr);
}

// function name must match progName when loading module from GO
int xdp_firewall(struct xdp_md *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    // drop packets
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    unsigned int srcIp;

    nh_off = sizeof(*eth);
	if (data + nh_off  > data_end) {
		bpf_trace_printk("Passing packet1");
        return XDP_PASS;
	}
    h_proto = eth->h_proto;

    nh_off = sizeof(*eth);
	if (h_proto == htons(ETH_P_IP)) {
		bpf_trace_printk("Found IPv4 packet");
		srcIp = get_src_ip(data, nh_off, data_end);
		bpf_trace_printk("Found src IP: %x", srcIp);
		value = block_ips.lookup(&srcIp);
		if(value != NULL) {
			// found IP to block
			return XDP_DROP;
		}
	}
	bpf_trace_printk("Not found IPv4 packet: %d\n", h_proto);
	return XDP_PASS;
}
`
