// KafkaProducerEngine.hpp
#pragma once
#include <iostream>
#include <string>
#include <memory>
#include <stdexcept>
#include <librdkafka/rdkafkacpp.h>

class DeliveryReportCallback : public RdKafka::DeliveryReportCb {
public:
    void dr_cb(RdKafka::Message &message) override {
        if (message.err()) {
            std::cerr << "[Kafka Producer] Message delivery failed: " 
                      << message.errstr() << std::endl;
        }
    }
};

class KafkaProducerEngine {
private:
    std::unique_ptr<RdKafka::Producer> producer_;
    DeliveryReportCallback delivery_callback_;
    std::string target_topic_;

public:
    KafkaProducerEngine(const std::string& brokers, const std::string& topic) 
        : target_topic_(topic) {
        std::string errstr;
        std::unique_ptr<RdKafka::Conf> conf(RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL));

        if (conf->set("bootstrap.servers", brokers, errstr)!= RdKafka::Conf::CONF_OK) {
            throw std::runtime_error("Kafka bootstrap configuration error: " + errstr);
        }

        if (conf->set("dr_cb", &delivery_callback_, errstr)!= RdKafka::Conf::CONF_OK) {
            throw std::runtime_error("Kafka callback registration error: " + errstr);
        }

        // Configure performance parameters for high-throughput edge logging [4, 23, 24]
        if (conf->set("queue.buffering.max.messages", "250000", errstr)!= RdKafka::Conf::CONF_OK ||
            conf->set("queue.buffering.max.kbytes", "1048576", errstr)!= RdKafka::Conf::CONF_OK || // 1GB Maximum Buffer
            conf->set("compression.codec", "lz4", errstr)!= RdKafka::Conf::CONF_OK ||
            conf->set("linger.ms", "15", errstr)!= RdKafka::Conf::CONF_OK) {
            std::cerr << " Performance tuning skipped: " << errstr << std::endl;
        }

        producer_.reset(RdKafka::Producer::create(conf.get(), errstr));
        if (!producer_) {
            throw std::runtime_error("Failed to build producer: " + errstr);
        }
    }

    ~KafkaProducerEngine() {
        // Flush remaining buffered events before shutting down [21]
        producer_->flush(10000);
    }

    void publish_alert(const std::string& message_payload) {
        RdKafka::ErrorCode err = producer_->produce(
            target_topic_,
            RdKafka::Topic::PARTITION_UA,
            RdKafka::Producer::RK_MSG_COPY, // Copy packet buffer explicitly [21, 22]
            const_cast<char*>(message_payload.c_str()), message_payload.size(),
            nullptr, 0,
            0,
            nullptr,
            nullptr
        );

        if (err!= RdKafka::ERR_NO_ERROR) {
            if (err == RdKafka::ERR__QUEUE_FULL) {
                // If the local buffer fills up, block briefly to allow transport [21]
                producer_->poll(500);
                publish_alert(message_payload); // Retry message delivery
            } else {
                std::cerr << "[Kafka Error] Message publishing failed: " << RdKafka::err2str(err) << std::endl;
            }
        }
        producer_->poll(0); // Poll for delivery reports [21]
    }
};
