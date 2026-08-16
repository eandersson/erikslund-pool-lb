#pragma once
// Immutable route snapshots and mutable per-backend health/load state.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "core/config.hpp"
#include "net/endpoint.hpp"

namespace erikslund::routing {

inline constexpr std::size_t kBackendCacheLineBytes = 64;

struct BackendState {
    std::string name;
    std::string pool;
    std::string configured_address;
    std::string configured_health_address;
    std::vector<net::SocketAddress> socket_addresses;
    std::vector<net::SocketAddress> health_socket_addresses;
    bool send_proxy_v2 = true;
    alignas(kBackendCacheLineBytes) std::atomic<bool> healthy{false};
    std::atomic<int> consecutive_successes{0};
    std::atomic<int> consecutive_failures{0};
    alignas(kBackendCacheLineBytes) std::atomic<std::uint64_t> active_connections{0};
    alignas(kBackendCacheLineBytes) std::atomic<std::uint64_t> connection_attempts{0};
    std::atomic<std::uint64_t> connection_errors{0};
};

struct PoolState {
    std::string name;
    std::vector<std::shared_ptr<BackendState>> backends;
};

struct RoutingTable {
    std::string active_pool;
    bool failover = true;
    core::HealthConfig health;
    std::vector<net::SocketAddress> upstream_source_addresses;
    std::vector<PoolState> pools;
    std::size_t active_pool_index = 0;
};

std::shared_ptr<RoutingTable> make_routing_table(
    const core::Config& config, const std::shared_ptr<const RoutingTable>& previous = {});
std::shared_ptr<BackendState> select_backend(const RoutingTable& table, std::uint64_t sequence);
bool has_routable_backend(const RoutingTable& table);

} // namespace erikslund::routing
