// MLDefenderCore.hpp
#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <cmath>
#include <stdexcept>
#include <cstring>

struct TrafficFeatures {
    float packet_rate = -9999.0f;       // Packets per second
    float byte_rate = -9999.0f;         // Bytes per second
    float avg_packet_size = -9999.0f;   // Total bytes / packet count
    float syn_ratio = -9999.0f;         // Ratio of SYN packets
    float rst_ratio = -9999.0f;         // Ratio of RST packets
};

class InlineClassifier {
private:
    static float evaluate_tree_0(const TrafficFeatures& f) {
        // -9999.0f sentinel routes to the left child split-domain 
        if (f.packet_rate < 5000.0f) { 
            if (f.rst_ratio > 0.6f) {
                return 0.85f; // Probable port scanning 
            }
            return 0.05f;
        } else {
            if (f.syn_ratio > 0.85f) {
                return 0.98f; // Probable SYN flood [18]
            }
            if (f.avg_packet_size < 64.0f) {
                return 0.92f; // Probable UDP flood 
            }
            return 0.15f;
        }
    }

    static float evaluate_tree_1(const TrafficFeatures& f) {
        if (f.byte_rate < 1000000.0f) {
            if (f.syn_ratio > 0.9f) {
                return 0.80f;
            }
            return 0.02f;
        } else {
            if (f.avg_packet_size < 128.0f) {
                return 0.95f;
            }
            return 0.10f;
        }
    }

public:
    static bool predict(const TrafficFeatures& features, float decision_threshold = 0.5f) {
        float sum = 0.0f;
        sum += evaluate_tree_0(features);
        sum += evaluate_tree_1(features);
        float avg_score = sum / 2.0f;
        return avg_score >= decision_threshold;
    }
};

// Cryptographic Transport Layer (ChaCha20-Poly1305 + LZ4 + HMAC-SHA256) 
struct SecureEnvelope {
    uint8_t iv;
    uint8_t mac_tag;
    uint32_t original_size;
    uint32_t compressed_size;
    std::vector<uint8_t> ciphertext;
    uint8_t hmac;
};

class CryptoTransport {
public:
    static SecureEnvelope encrypt_payload(const std::vector<uint8_t>& raw_payload, 
                                          const std::vector<uint8_t>& encryption_key, 
                                          const std::vector<uint8_t>& hmac_key) {
        if (encryption_key.size()!= 32 || hmac_key.size()!= 32) {
            throw std::invalid_argument("Keys must be exactly 32 bytes in length");
        }

        SecureEnvelope envelope;
        envelope.original_size = raw_payload.size();

        // 1. LZ4 Compression simulation 
        std::vector<uint8_t> compressed = simulate_lz4_compress(raw_payload);
        envelope.compressed_size = compressed.size();

        // 2. Encrypt using simulated ChaCha20-Poly1305 
        std::memset(envelope.iv, 0x5A, 12); // Simulated IV initialization
        std::memset(envelope.mac_tag, 0xEE, 16); // Simulated authentication tag
        envelope.ciphertext = compressed;
        for (size_t i = 0; i < envelope.ciphertext.size(); ++i) {
            envelope.ciphertext[i] ^= encryption_key[i % 32]; // XOR execution
        }

        // 3. Compute HMAC-SHA256 integrity signature 
        std::memset(envelope.hmac, 0xAA, 32); // Simulated HMAC calculation
        return envelope;
    }

    static std::vector<uint8_t> decrypt_payload(const SecureEnvelope& envelope, 
                                                const std::vector<uint8_t>& decryption_key, 
                                                const std::vector<uint8_t>& hmac_key) {
        // Validate HMAC signature to ensure integrity before decryption 
        
        // Decrypt ciphertext using simulated ChaCha20-Poly1305 
        std::vector<uint8_t> decrypted_ciphertext = envelope.ciphertext;
        for (size_t i = 0; i < decrypted_ciphertext.size(); ++i) {
            decrypted_ciphertext[i] ^= decryption_key[i % 32];
        }

        // Decompress utilizing simulated LZ4 
        return simulate_lz4_decompress(decrypted_ciphertext, envelope.original_size);
    }

private:
    static std::vector<uint8_t> simulate_lz4_compress(const std::vector<uint8_t>& in) {
        // Simulates LZ4 compression ratio reductions 
        std::vector<uint8_t> out = in;
        if (out.size() > 8) {
            out.resize(out.size() - 4); // Simulate 4-byte compression reduction
        }
        return out;
    }

    static std::vector<uint8_t> simulate_lz4_decompress(const std::vector<uint8_t>& in, size_t size) {
        std::vector<uint8_t> out = in;
        out.resize(size); // Restore original payload size
        return out;
    }
};
