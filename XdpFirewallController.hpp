// XdpFirewallController.hpp
#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>

class XdpFirewallController {
private:
    struct bpf_object* obj_ = nullptr;
    int program_fd_ = -1;
    int blocklist_map_fd_ = -1;
    int stats_map_fd_ = -1;
    unsigned int if_index_ = 0;

public:
    XdpFirewallController(const std::string& interface, const std::string& bpf_object_path) {
        // Resolve network interface index from interface name [15]
        if_index_ = if_nametoindex(interface.c_str());
        if (if_index_ == 0) {
            throw std::runtime_error("Failed to find interface: " + interface);
        }

        // Open and parse the eBPF object file 
        obj_ = bpf_object__open_file(bpf_object_path.c_str(), nullptr);
        if (!obj_) {
            throw std::runtime_error("Failed to parse BPF object file: " + bpf_object_path);
        }

        // Load the parsed structures into the kernel
        if (bpf_object__load(obj_)) {
            bpf_object__close(obj_);
            throw std::runtime_error("Failed to load eBPF bytecode into kernel space");
        }

        // Locate the program entry point [13]
        struct bpf_program* prog = bpf_object__find_program_by_name(obj_, "xdp_mitigate_prog");
        if (!prog) {
            bpf_object__close(obj_);
            throw std::runtime_error("Failed to locate entry program 'xdp_mitigate_prog'");
        }
        program_fd_ = bpf_program__fd(prog);

        // Resolve shared map file descriptors [13]
        blocklist_map_fd_ = bpf_object__find_map_fd_by_name(obj_, "ip_blocklist");
        stats_map_fd_ = bpf_object__find_map_fd_by_name(obj_, "drop_stats");

        if (blocklist_map_fd_ < 0 || stats_map_fd_ < 0) {
            bpf_object__close(obj_);
            throw std::runtime_error("Failed to resolve key kernel map file descriptors");
        }
    }

    ~XdpFirewallController() {
        detach_from_link();
        if (obj_) {
            bpf_object__close(obj_);
        }
    }

    // Attach XDP program to link 
    void attach_to_link(uint32_t xdp_flags) {
        int err = bpf_xdp_attach(if_index_, program_fd_, xdp_flags, nullptr);
        if (err < 0) {
            throw std::runtime_error("Failed to attach XDP to interface index " + std::to_string(if_index_));
        }
        std::cout << " Program attached to interface index " << if_index_ << std::endl;
    }

    void detach_from_link() {
        if (if_index_ > 0) {
            bpf_xdp_detach(if_index_, 0, nullptr);
            std::cout << " Program detached from interface index " << if_index_ << std::endl;
        }
    }

    // Add a blocked IP address to the shared map 
    bool insert_block_rule(const std::string& ip_address) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_address.c_str(), &addr)!= 1) {
            std::cerr << " Invalid IP address format: " << ip_address << std::endl;
            return false;
        }

        __u32 key = addr.s_addr; // Store in Network Byte Order
        __u64 initial_drops = 0;

        int err = bpf_map_update_elem(blocklist_map_fd_, &key, &initial_drops, BPF_ANY);
        if (err < 0) {
            std::cerr << " Map insertion failed for: " << ip_address << std::endl;
            return false;
        }
        return true;
    }

    bool remove_block_rule(const std::string& ip_address) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_address.c_str(), &addr)!= 1) {
            return false;
        }

        __u32 key = addr.s_addr;
        int err = bpf_map_delete_elem(blocklist_map_fd_, &key);
        if (err < 0) {
            return false;
        }
        return true;
    }

    // Query drop stats aggregated from all CPU core maps [13]
    uint64_t get_aggregate_drops() {
        __u32 key = 0;
        int num_cpus = libbpf_num_possible_cpus();
        std::vector<__u64> values(num_cpus);

        int err = bpf_map_lookup_elem(stats_map_fd_, &key, values.data());
        if (err < 0) {
            return 0;
        }

        uint64_t total = 0;
        for (int i = 0; i < num_cpus; ++i) {
            total += values[i];
        }
        return total;
    }
};
