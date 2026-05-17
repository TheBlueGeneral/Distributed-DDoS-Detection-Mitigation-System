// ShardedFlowManager.hpp
#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

// MurmurHash3 32-bit implementation for fast, collision-resistant indexing [16, 17]
inline uint32_t murmur_hash3_32(const void* key, int len, uint32_t seed = 0x9747b28c) {
    const uint8_t* data = (const uint8_t*)key;
    const int nblocks = len / 4;
    uint32_t h1 = seed;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    const uint32_t* blocks = (const uint32_t*)(data + nblocks * 4);
    for (int i = -nblocks; i; i++) {
        uint32_t k1 = blocks[i];
        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> 17); // Fast bitwise rotation
        k1 *= c2;
        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> 19);
        h1 = h1 * 5 + 0xe6546b64;
    }

    const uint8_t* tail = (const uint8_t*)(data + nblocks * 4);
    uint32_t k1 = 0;
    switch (len & 3) {
        case 3: k1 ^= tail << 16;
        case 2: k1 ^= tail << 8;
        case 1: k1 ^= tail;
                k1 *= c1;
                k1 = (k1 << 15) | (k1 >> 17);
                k1 *= c2;
                h1 ^= k1;
    }

    h1 ^= len;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;
    return h1;
}

struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;

    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

struct FlowKeyHasher {
    std::size_t operator()(const FlowKey& key) const {
        return murmur_hash3_32(&key, sizeof(FlowKey));
    }
};

struct FlowMetrics {
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_seen;
    uint32_t syn_count = 0;
    uint32_t rst_count = 0;
    uint32_t ack_count = 0;
};

class FlowShard {
private:
    std::unordered_map<FlowKey, FlowMetrics, FlowKeyHasher> flows_;
    mutable std::shared_mutex mutex_;

public:
    void update_flow(const FlowKey& key, uint32_t packet_len, bool is_syn, bool is_ack, bool is_rst) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();
        auto& metrics = flows_[key];
        
        if (metrics.packet_count == 0) {
            metrics.start_time = now;
        }
        metrics.packet_count++;
        metrics.byte_count += packet_len;
        metrics.last_seen = now;
        
        if (is_syn) metrics.syn_count++;
        if (is_ack) metrics.ack_count++;
        if (is_rst) metrics.rst_count++;
    }

    std::vector<std::pair<FlowKey, FlowMetrics>> extract_and_flush(uint64_t idle_timeout_ms) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        std::vector<std::pair<FlowKey, FlowMetrics>> expired_flows;
        auto now = std::chrono::steady_clock::now();

        for (auto it = flows_.begin(); it!= flows_.end();) {
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - it->second.last_seen
            ).count();
            
            if (duration >= static_cast<long long>(idle_timeout_ms)) {
                expired_flows.push_back(*it);
                it = flows_.erase(it); // Thread-safe deletion 
            } else {
                ++it;
            }
        }
        return expired_flows;
    }
};

class ShardedFlowManager {
private:
    std::vector<FlowShard> shards_;
    size_t num_shards_;

    size_t get_shard_index(const FlowKey& key) const {
        FlowKeyHasher hasher;
        return hasher(key) % num_shards_;
    }

public:
    explicit ShardedFlowManager(size_t num_shards) 
        : num_shards_(num_shards), shards_(num_shards) {}

    void process_packet(const FlowKey& key, uint32_t packet_len, bool is_syn = false, bool is_ack = false, bool is_rst = false) {
        size_t idx = get_shard_index(key);
        shards_[idx].update_flow(key, packet_len, is_syn, is_ack, is_rst);
    }

    // Dynamic, thread-safe lock-striped polling 
    std::vector<std::pair<FlowKey, FlowMetrics>> reap_expired_flows(uint64_t idle_timeout_ms) {
        std::vector<std::pair<FlowKey, FlowMetrics>> all_expired;
        for (auto& shard : shards_) {
            auto expired = shard.extract_and_flush(idle_timeout_ms);
            all_expired.insert(all_expired.end(), expired.begin(), expired.end());
        }
        return all_expired;
    }
};
