// main.cpp
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <csignal>
#include <vector>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ShardedFlowManager.hpp"
#include "KafkaProducerEngine.hpp"
#include "RedisSyncController.hpp"
#include "MLDefenderCore.hpp"

#ifdef RUN_XDP
#include "XdpFirewallController.hpp"
#endif

std::atomic<bool> g_shutdown(false);

void handle_termination(int signal) {
    g_shutdown = true;
}

void execution_loop(const std::string& network_interface, const std::string& kafka_brokers, 
                    const std::string& redis_host, int redis_port) {
    std::cout << "[Edge Guard] Initializing Platform Ingestion Pipeline..." << std::endl;

    // Allocate 32 isolated flow-tracking shards 
    ShardedFlowManager flow_manager(32);

    // Initialize the Kafka Producer engine [12, 21]
    std::unique_ptr<KafkaProducerEngine> kafka_broker;
    try {
        kafka_broker = std::make_unique<KafkaProducerEngine>(kafka_brokers, "network_alerts");
        std::cout << "[Edge Guard] Connected to Kafka Cluster successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[Kafka Conn Error] " << e.what() << " (Running without remote logging)." << std::endl;
    }

    // Initialize the Redis state synchronization cache [10, 27]
    std::unique_ptr<RedisSyncController> redis_cache;
    try {
        redis_cache = std::make_unique<RedisSyncController>(redis_host, redis_port);
        std::cout << "[Edge Guard] Connected to Redis Cache successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << " " << e.what() << " (Running without state sync)." << std::endl;
    }

#ifdef RUN_XDP
    // Load and attach the eBPF/XDP firewall to the interface 
    std::unique_ptr<XdpFirewallController> xdp_firewall;
    try {
        xdp_firewall = std::make_unique<XdpFirewallController>(network_interface, "./xdp_firewall_kernel.o");
        xdp_firewall->attach_to_link(2); // Attach in generic mode 
        std::cout << "[Edge Guard] eBPF/XDP firewall loaded into kernel." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << " " << e.what() << " (Kernel mitigation disabled)." << std::endl;
    }
#endif

    // Simulated ingestion thread to represent high-rate edge packet processing [18, 34]
    std::thread ingestion_simulation([&flow_manager]() {
        uint32_t malicious_ips = {0x0100000a, 0x0200000a, 0x0300000a}; // 10.0.0.1, 10.0.0.2, 10.0.0.3
        uint32_t simulated_destination = 0xfe00000a; // 10.0.0.254
        
        while (!g_shutdown) {
            FlowKey key;
            bool trigger_attack = (rand() % 100) < 15; // Simulate periodic SYN floods [18]
            
            if (trigger_attack) {
                key.src_ip = malicious_ips[rand() % 3];
                key.src_port = static_cast<uint16_t>(5000 + (rand() % 1000));
            } else {
                key.src_ip = 0x5500000a; // 10.0.0.85
                key.src_port = 443;
            }
            
            key.dst_ip = simulated_destination;
            key.dst_port = 80;
            key.protocol = IPPROTO_TCP;

            flow_manager.process_packet(key, 64, trigger_attack,!trigger_attack, false);
            std::this_thread::sleep_for(std::chrono::microseconds(100)); // Simulate traffic interval
        }
    });

    // Main telemetry aggregation and classification loop 
    while (!g_shutdown) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Reap flow states inactive for more than 1000ms 
        auto captured_flows = flow_manager.reap_expired_flows(1000);

        for (const auto& flow : captured_flows) {
            const auto& key = flow.first;
            const auto& metrics = flow.second;

            double window_sec = 1.0;
            TrafficFeatures f;
            f.packet_rate = static_cast<float>(metrics.packet_count / window_sec);
            f.byte_rate = static_cast<float>(metrics.byte_count / window_sec);
            f.avg_packet_size = metrics.packet_count > 0? static_cast<float>(metrics.byte_count / metrics.packet_count) : -9999.0f;
            f.syn_ratio = metrics.packet_count > 0? static_cast<float>(metrics.syn_count) / metrics.packet_count : -9999.0f;
            f.rst_ratio = metrics.packet_count > 0? static_cast<float>(metrics.rst_count) / metrics.packet_count : -9999.0f;

            // Run compiled Random Forest classifier 
            bool threat_detected = InlineClassifier::predict(f);

            struct in_addr source_ip_addr;
            source_ip_addr.s_addr = key.src_ip;
            std::string source_ip_str = inet_ntoa(source_ip_addr);

            // Run sliding-window rate checks on the shared Redis cache 
            bool rate_limit_exceeded = false;
            if (redis_cache) {
                rate_limit_exceeded =!redis_cache->check_sliding_window_rate(source_ip_str, 800, 1);
            }

            if (threat_detected || rate_limit_exceeded) {
                std::cout << " Host " << source_ip_str 
                          << " flagged" << std::endl;

                // Broadcast block rule to other edge nodes via Redis 
                if (redis_cache) {
                    if (!redis_cache->check_global_blocklist(source_ip_str)) {
                        redis_cache->broadcast_block_rule(source_ip_str, 600); // 10-minute block
                        std::cout << " Broadcasted block rule for: " << source_ip_str << std::endl;
                    }
                }

#ifdef RUN_XDP
                // Block traffic locally at driver layer using XDP [13]
                if (xdp_firewall) {
                    xdp_firewall->insert_block_rule(source_ip_str);
                    std::cout << "[Local Mitigation] Blocked " << source_ip_str << " in kernel-space." << std::endl;
                }
#endif

                // Send security alert details to the Kafka logging cluster [7, 12]
                if (kafka_broker) {
                    std::string payload = "{\"src_ip\":\"" + source_ip_str + 
                                          "\",\"avg_size\":" + std::to_string(f.avg_packet_size) +
                                          ",\"status\":\"MITIGATED\"}";
                    kafka_broker->publish_alert(payload);
                }
            }
        }
    }

    if (ingestion_simulation.joinable()) {
        ingestion_simulation.join();
    }
}

int main(int argc, char** argv) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv << " <interface> <kafka_brokers> <redis_host> <redis_port>" << std::endl;
        return 1;
    }

    std::signal(SIGINT, handle_termination);
    std::signal(SIGTERM, handle_termination);

    std::string interface = argv;
    std::string brokers = argv;
    std::string redis_host = argv;
    int redis_port = std::stoi(argv);

    try {
        execution_loop(interface, brokers, redis_host, redis_port);
    } catch (const std::exception& e) {
        std::cerr << "[Edge Guard Critical] System crash: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "[Edge Guard] System exited cleanly." << std::endl;
    return 0;
}
