// xdp_firewall_kernel.c
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

// Shared BPF map containing blocked IP addresses 
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);        // Key: IPv4 source address (Network Byte Order)
    __type(value, __u64);      // Value: Monotonically increasing drop counter
    __uint(max_entries, 65536);
} ip_blocklist SEC(".maps");

// Per-CPU drop statistic counter map [13]
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);        // Key: Constant 0 index
    __type(value, __u64);      // Value: Accumulated drop count
    __uint(max_entries, 1);
} drop_stats SEC(".maps");

SEC("xdp_mitigate")
int xdp_mitigate_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Boundary check: Verify Ethernet header fits within packet bounds 
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Bypass non-IPv4 traffic [13, 15]
    if (eth->h_proto!= bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Boundary check: Verify IPv4 header fits within packet bounds 
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 src_ip = iph->saddr;

    // Check if the source IP is present in the blocklist map 
    __u64 *drop_counter = bpf_map_lookup_elem(&ip_blocklist, &src_ip);
    if (drop_counter) {
        // Increment the drop counter atomically
        __sync_fetch_and_add(drop_counter, 1);

        // Update the per-CPU drop statistics [13]
        __u32 stats_key = 0;
        __u64 *cpu_counter = bpf_map_lookup_elem(&drop_stats, &stats_key);
        if (cpu_counter) {
            __sync_fetch_and_add(cpu_counter, 1);
        }
        return XDP_DROP; // Drop packet in kernel space immediately 
    }

    return XDP_PASS; // Pass legitimate traffic to network stack 
}

char _license SEC("license") = "GPL";
