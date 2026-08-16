#include "core/config.hpp"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <format>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>

#include <arpa/inet.h>

#include <glaze/glaze.hpp>
#include <glaze/yaml.hpp>

#include "core/errors.hpp"
#include "net/endpoint.hpp"

template <> struct glz::meta<erikslund::core::LimitsConfig> {
    using T = erikslund::core::LimitsConfig;
    static constexpr auto value = glz::object(
        "max_connections", &T::max_connections,
        "max_connections_per_ip", &T::max_connections_per_ip,
        "connections_per_second_per_ip", &T::connections_per_second_per_ip,
        "connection_burst_per_ip", &T::connection_burst_per_ip,
        "global_connections_per_second", &T::global_connections_per_second,
        "global_connection_burst", &T::global_connection_burst,
        "ipv6_prefix_bits", &T::ipv6_prefix_bits,
        "max_tracked_client_ips", &T::max_tracked_client_ips,
        "client_state_retention_seconds", &T::client_state_retention_seconds,
        "messages_per_second_per_connection", &T::messages_per_second_per_connection,
        "message_burst_per_connection", &T::message_burst_per_connection,
        "bytes_per_second_per_connection", &T::bytes_per_second_per_connection,
        "byte_burst_per_connection", &T::byte_burst_per_connection,
        "messages_per_second_per_ip", &T::messages_per_second_per_ip,
        "message_burst_per_ip", &T::message_burst_per_ip,
        "bytes_per_second_per_ip", &T::bytes_per_second_per_ip,
        "byte_burst_per_ip", &T::byte_burst_per_ip,
        "max_messages_per_ready_event", &T::max_messages_per_ready_event,
        "max_line_bytes", &T::max_line_bytes,
        "max_buffer_bytes", &T::max_buffer_bytes,
        "max_queued_bytes", &T::max_queued_bytes,
        "tls_handshake_timeout_seconds", &T::tls_handshake_timeout_seconds,
        "first_message_timeout_seconds", &T::first_message_timeout_seconds,
        "upstream_connect_timeout_milliseconds", &T::upstream_connect_timeout_milliseconds,
        "idle_timeout_seconds", &T::idle_timeout_seconds);
};

namespace erikslund::core {

namespace {

void require_positive(int value, std::string_view name) {
    if (value <= 0)
        throw ConfigError(std::string(name) + " must be greater than zero");
}

void require_positive(std::size_t value, std::string_view name) {
    if (value == 0)
        throw ConfigError(std::string(name) + " must be greater than zero");
}

void require_positive(double value, std::string_view name) {
    if (!std::isfinite(value) || value <= 0.0)
        throw ConfigError(std::string(name) + " must be finite and greater than zero");
}

void validate_method_list(const std::vector<std::string>& methods, std::string_view name) {
    if (methods.size() > kMaximumAdditionalProtocolMethods)
        throw ConfigError(std::format("{} must contain at most {} entries", name,
                                      kMaximumAdditionalProtocolMethods));

    std::unordered_set<std::string_view> unique_methods;
    for (const std::string& method : methods) {
        if (!method.starts_with("mining.") ||
            method.size() <= std::string_view("mining.").size() ||
            method.size() > kMaximumProtocolMethodBytes)
            throw ConfigError(std::format(
                "{} entries must use the mining.* namespace and be at most {} bytes", name,
                kMaximumProtocolMethodBytes));
        if (!std::ranges::all_of(method, [](char character) {
                const auto byte = static_cast<unsigned char>(character);
                return byte >= 0x20 && byte <= 0x7e;
            }))
            throw ConfigError(std::string(name) + " entries must contain printable ASCII only");
        if (!unique_methods.insert(method).second)
            throw ConfigError(std::format("{} must not contain duplicates: {}", name, method));
    }
}

std::string numeric_address_key(const std::string& address) {
    in_addr ipv4{};
    if (::inet_pton(AF_INET, address.c_str(), &ipv4) == 1) {
        std::string key(1, '\x04');
        key.append(reinterpret_cast<const char*>(&ipv4), sizeof(ipv4));
        return key;
    }

    in6_addr ipv6{};
    if (::inet_pton(AF_INET6, address.c_str(), &ipv6) == 1) {
        std::string key(1, '\x06');
        key.append(reinterpret_cast<const char*>(&ipv6), sizeof(ipv6));
        return key;
    }
    throw ConfigError("upstream_source_addresses entries must be numeric IPv4 or IPv6 "
                      "addresses without ports: " +
                      address);
}

void validate_upstream_source_addresses(const std::vector<std::string>& addresses) {
    if (addresses.size() > kMaximumUpstreamSourceAddresses)
        throw ConfigError(std::format("upstream_source_addresses must contain at most {} entries",
                                      kMaximumUpstreamSourceAddresses));

    std::unordered_set<std::string> unique_addresses;
    unique_addresses.reserve(addresses.size());
    for (const std::string& address : addresses) {
        if (address.empty())
            throw ConfigError("upstream_source_addresses entries must not be empty");
        if (!unique_addresses.insert(numeric_address_key(address)).second)
            throw ConfigError("upstream_source_addresses must contain unique addresses: " +
                              address);
    }
}

void validate(Config& config) {
    if (config.listeners.empty())
        throw ConfigError("listeners must contain at least one entry");
    if (config.pools.empty())
        throw ConfigError("pools must contain at least one entry");
    if (config.active_pool.empty())
        throw ConfigError("active_pool must not be empty");

    std::unordered_set<std::string> listener_names;
    std::unordered_set<std::string> listener_addresses;
    for (const ListenerConfig& listener : config.listeners) {
        if (listener.name.empty() || !listener_names.insert(listener.name).second)
            throw ConfigError("listener names must be non-empty and unique");
        net::parse_endpoint(listener.address);
        if (!listener_addresses.insert(listener.address).second)
            throw ConfigError("listener addresses must be unique: " + listener.address);
        if (listener.tls && (listener.certificate_file.empty() || listener.private_key_file.empty()))
            throw ConfigError("TLS listener " + listener.name +
                              " requires certificate_file and private_key_file");
    }

    std::unordered_set<std::string> pool_names;
    std::unordered_set<std::string> backend_names;
    for (const PoolConfig& pool : config.pools) {
        if (pool.name.empty() || !pool_names.insert(pool.name).second)
            throw ConfigError("pool names must be non-empty and unique");
        if (pool.backends.empty())
            throw ConfigError("pool " + pool.name + " must contain at least one backend");
        for (const BackendConfig& backend : pool.backends) {
            if (backend.name.empty() || !backend_names.insert(backend.name).second)
                throw ConfigError("backend names must be non-empty and globally unique");
            net::parse_endpoint(backend.address);
            if (!backend.health_address.empty())
                net::parse_endpoint(backend.health_address);
        }
    }
    if (!pool_names.contains(config.active_pool))
        throw ConfigError("active_pool does not name a configured pool: " + config.active_pool);

    validate_upstream_source_addresses(config.upstream_source_addresses);
    net::parse_endpoint(config.api_address);
    if (config.io_workers < 0 || config.io_workers > 256)
        throw ConfigError("io_workers must be in [0, 256]");
    require_positive(config.health.interval_seconds, "health.interval_seconds");
    require_positive(config.health.connect_timeout_milliseconds,
                     "health.connect_timeout_milliseconds");
    require_positive(config.health.rise_checks, "health.rise_checks");
    require_positive(config.health.fall_checks, "health.fall_checks");
    require_positive(config.limits.max_connections, "limits.max_connections");
    require_positive(config.limits.max_connections_per_ip,
                     "limits.max_connections_per_ip");
    require_positive(config.limits.connections_per_second_per_ip,
                     "limits.connections_per_second_per_ip");
    require_positive(config.limits.connection_burst_per_ip,
                     "limits.connection_burst_per_ip");
    require_positive(config.limits.global_connections_per_second,
                     "limits.global_connections_per_second");
    require_positive(config.limits.global_connection_burst,
                     "limits.global_connection_burst");
    if (config.limits.ipv6_prefix_bits < 1 || config.limits.ipv6_prefix_bits > 128)
        throw ConfigError("limits.ipv6_prefix_bits must be in [1, 128]");
    require_positive(config.limits.max_tracked_client_ips,
                     "limits.max_tracked_client_ips");
    require_positive(config.limits.client_state_retention_seconds,
                     "limits.client_state_retention_seconds");
    require_positive(config.limits.messages_per_second_per_connection,
                     "limits.messages_per_second_per_connection");
    require_positive(config.limits.message_burst_per_connection,
                     "limits.message_burst_per_connection");
    require_positive(config.limits.bytes_per_second_per_connection,
                     "limits.bytes_per_second_per_connection");
    require_positive(config.limits.byte_burst_per_connection,
                     "limits.byte_burst_per_connection");
    require_positive(config.limits.messages_per_second_per_ip,
                     "limits.messages_per_second_per_ip");
    require_positive(config.limits.message_burst_per_ip,
                     "limits.message_burst_per_ip");
    require_positive(config.limits.bytes_per_second_per_ip,
                     "limits.bytes_per_second_per_ip");
    require_positive(config.limits.byte_burst_per_ip, "limits.byte_burst_per_ip");
    require_positive(config.limits.max_messages_per_ready_event,
                     "limits.max_messages_per_ready_event");
    require_positive(config.limits.max_line_bytes, "limits.max_line_bytes");
    if (config.limits.max_buffer_bytes < config.limits.max_line_bytes)
        throw ConfigError("limits.max_buffer_bytes must be at least limits.max_line_bytes");
    if (config.limits.max_queued_bytes < config.limits.max_buffer_bytes)
        throw ConfigError("limits.max_queued_bytes must be at least limits.max_buffer_bytes");
    require_positive(config.limits.tls_handshake_timeout_seconds,
                     "limits.tls_handshake_timeout_seconds");
    require_positive(config.limits.first_message_timeout_seconds,
                     "limits.first_message_timeout_seconds");
    require_positive(config.limits.upstream_connect_timeout_milliseconds,
                     "limits.upstream_connect_timeout_milliseconds");
    require_positive(config.limits.idle_timeout_seconds, "limits.idle_timeout_seconds");
    if (config.protocol.max_json_depth < 2 || config.protocol.max_json_depth > 128)
        throw ConfigError("protocol.max_json_depth must be in [2, 128]");
    validate_method_list(config.protocol.additional_allowed_methods,
                         "protocol.additional_allowed_methods");
    validate_method_list(config.protocol.additional_initial_methods,
                         "protocol.additional_initial_methods");
    const std::unordered_set<std::string_view> allowed_methods(
        config.protocol.additional_allowed_methods.begin(),
        config.protocol.additional_allowed_methods.end());
    for (const std::string& method : config.protocol.additional_initial_methods)
        if (!allowed_methods.contains(method))
            throw ConfigError("protocol.additional_initial_methods entry is not present in "
                              "protocol.additional_allowed_methods: " +
                              method);
}

} // namespace

Config Config::from_string(const std::string& text) {
    Config config;
    if (const auto error = glz::read_yaml(config, text))
        throw ConfigError("invalid config: " + glz::format_error(error, text));
    validate(config);
    return config;
}

Config Config::from_file(const std::string& path) {
    std::ifstream stream(path);
    if (!stream)
        throw ConfigError("cannot open config file: " + path);
    std::stringstream buffer;
    buffer << stream.rdbuf();
    return from_string(buffer.str());
}

std::vector<std::string> Config::restart_required_changes(const Config& replacement) const {
    std::vector<std::string> changes;
    const bool same_listener_topology =
        std::ranges::equal(listeners, replacement.listeners,
                           [](const ListenerConfig& current,
                              const ListenerConfig& candidate) {
                               return current.name == candidate.name &&
                                      current.address == candidate.address &&
                                      current.tls == candidate.tls;
                           });
    if (!same_listener_topology)
        changes.emplace_back("listeners");
    if (api_address != replacement.api_address)
        changes.emplace_back("api_address");
    if (io_workers != replacement.io_workers)
        changes.emplace_back("io_workers");
    return changes;
}

} // namespace erikslund::core
