#pragma once
// YAML service configuration and validation.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace erikslund::core {

struct ListenerConfig {
    std::string name;
    std::string address;
    bool tls = false;
    std::string certificate_file;
    std::string private_key_file;

    bool operator==(const ListenerConfig&) const = default;
};

struct BackendConfig {
    std::string name;
    std::string address;
    std::string health_address;
    bool send_proxy_v2 = true;
};

struct PoolConfig {
    std::string name;
    std::vector<BackendConfig> backends;
};

struct HealthConfig {
    int interval_seconds = 5;
    int connect_timeout_milliseconds = 1'000;
    int rise_checks = 2;
    int fall_checks = 3;
};

struct LimitsConfig {
    std::size_t max_connections = 100'000;
    std::size_t max_connections_per_ip = 32;
    double connections_per_second_per_ip = 4.0;
    std::size_t connection_burst_per_ip = 16;
    double global_connections_per_second = 5'000.0;
    std::size_t global_connection_burst = 20'000;
    int ipv6_prefix_bits = 64;
    std::size_t max_tracked_client_ips = 262'144;
    int client_state_retention_seconds = 300;
    double messages_per_second_per_connection = 32.0;
    std::size_t message_burst_per_connection = 128;
    double bytes_per_second_per_connection = 262'144.0;
    std::size_t byte_burst_per_connection = 524'288;
    double messages_per_second_per_ip = 512.0;
    std::size_t message_burst_per_ip = 2'048;
    double bytes_per_second_per_ip = 4'194'304.0;
    std::size_t byte_burst_per_ip = 16'777'216;
    std::size_t max_messages_per_ready_event = 256;
    std::size_t max_line_bytes = 16'384;
    std::size_t max_buffer_bytes = 262'144;
    // Shared across both directions and all sessions to prevent distributed stalled peers from
    // turning the per-session buffer bound into an unbounded process-memory multiplier.
    std::size_t max_queued_bytes = 268'435'456;
    int tls_handshake_timeout_seconds = 10;
    int first_message_timeout_seconds = 10;
    int upstream_connect_timeout_milliseconds = 3'000;
    int idle_timeout_seconds = 3'600;
};

inline constexpr std::size_t kMaximumAdditionalProtocolMethods = 64;
inline constexpr std::size_t kMaximumProtocolMethodBytes = 128;
inline constexpr std::size_t kMaximumUpstreamSourceAddresses = 64;

struct ProtocolConfig {
    bool allow_unknown_mining_methods = false;
    std::vector<std::string> additional_allowed_methods;
    std::vector<std::string> additional_initial_methods;
    int max_json_depth = 32;
};

struct Config {
    std::vector<ListenerConfig> listeners;
    std::vector<PoolConfig> pools;
    std::string active_pool;
    bool failover = true;
    std::vector<std::string> upstream_source_addresses;
    std::string api_address = "127.0.0.1:7778";
    // 0 selects one reactor per available CPU, capped to avoid accidental oversubscription.
    int io_workers = 0;
    HealthConfig health;
    LimitsConfig limits;
    ProtocolConfig protocol;

    static Config from_string(const std::string& text);
    static Config from_file(const std::string& path);

    [[nodiscard]] std::vector<std::string> restart_required_changes(
        const Config& replacement) const;
};

} // namespace erikslund::core
