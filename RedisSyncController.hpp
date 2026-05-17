// RedisSyncController.hpp
#pragma once
#include <iostream>
#include <string>
#include <stdexcept>
#include <chrono>
#include <vector>
#include <hiredis/hiredis.h>

class RedisSyncController {
private:
    redisContext* ctx_ = nullptr;
    std::string host_;
    int port_;

    void reconnect() {
        if (ctx_) {
            redisFree(ctx_);
            ctx_ = nullptr;
        }
        ctx_ = redisConnect(host_.c_str(), port_);
        if (ctx_ == nullptr || ctx_->err) {
            std::string err_str = ctx_? ctx_->errstr : "Allocation failure";
            throw std::runtime_error("Redis connection failed: " + err_str);
        }
    }

public:
    RedisSyncController(const std::string& host, int port) 
        : host_(host), port_(port) {
        reconnect();
    }

    ~RedisSyncController() {
        if (ctx_) {
            redisFree(ctx_);
        }
    }

    // Sliding-window check using Redis sorted sets 
    bool check_sliding_window_rate(const std::string& ip_address, int max_packets_per_window, int window_size_sec = 1) {
        if (!ctx_ || ctx_->err) {
            try {
                reconnect();
            } catch (...) {
                return true; // Fail-open safety fallback to prevent blocking legitimate traffic
            }
        }

        auto now = std::chrono::system_clock::now();
        long long current_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()
        ).count();
        long long boundary_time_ms = current_time_ms - (window_size_sec * 1000);

        std::string key = "rate:" + ip_address;

        // Atomic pipeline execution to prune and append timestamps [10, 26]
        redisAppendCommand(ctx_, "MULTI");
        redisAppendCommand(ctx_, "ZREMRANGEBYSCORE %s -inf %lld", key.c_str(), boundary_time_ms);
        redisAppendCommand(ctx_, "ZADD %s %lld %lld", key.c_str(), current_time_ms, current_time_ms);
        redisAppendCommand(ctx_, "ZCARD %s", key.c_str());
        redisAppendCommand(ctx_, "EXPIRE %s %d", key.c_str(), window_size_sec + 2);
        redisAppendCommand(ctx_, "EXEC");

        // Drain responses from the pipeline buffers [26, 27]
        redisReply* reply = nullptr;
        for (int i = 0; i < 5; ++i) {
            if (redisGetReply(ctx_, (void**)&reply) == REDIS_OK && reply) {
                freeReplyObject(reply);
            }
        }

        bool rate_ok = true;
        if (redisGetReply(ctx_, (void**)&reply) == REDIS_OK && reply) {
            if (reply->type == REDIS_REPLY_ARRAY && reply->elements > 3) {
                // Read the ZCARD output (element index 2) to get the active window count [26]
                redisReply* zcard_reply = reply->element;
                if (zcard_reply->type == REDIS_REPLY_INTEGER) {
                    if (zcard_reply->integer > max_packets_per_window) {
                        rate_ok = false;
                    }
                }
            }
            freeReplyObject(reply);
        } else {
            reconnect();
        }

        return rate_ok;
    }

    // Sync a blocklist rule across other nodes via a Pub/Sub broadcast 
    void broadcast_block_rule(const std::string& ip_address, int duration_sec) {
        if (!ctx_ || ctx_->err) return;

        // Apply rule to the shared blocklist set 
        redisReply* reply = (redisReply*)redisCommand(ctx_, "SET blocked:%s 1 EX %d", ip_address.c_str(), duration_sec);
        if (reply) {
            freeReplyObject(reply);
        }

        // Publish event to notify other edge nodes immediately [25]
        reply = (redisReply*)redisCommand(ctx_, "PUBLISH blocklist_sync_channel %s", ip_address.c_str());
        if (reply) {
            freeReplyObject(reply);
        }
    }

    bool check_global_blocklist(const std::string& ip_address) {
        if (!ctx_ || ctx_->err) return false;
        redisReply* reply = (redisReply*)redisCommand(ctx_, "EXISTS blocked:%s", ip_address.c_str());
        bool blocked = false;
        if (reply) {
            if (reply->type == REDIS_REPLY_INTEGER && reply->integer > 0) {
                blocked = true;
            }
            freeReplyObject(reply);
        }
        return blocked;
    }
};
