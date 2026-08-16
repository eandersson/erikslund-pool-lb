#include "routing/router.hpp"

#include <algorithm>
#include <limits>
#include <string_view>

#include "core/errors.hpp"

namespace erikslund::routing {

namespace {

std::shared_ptr<BackendState> reusable_backend(const std::shared_ptr<const RoutingTable>& previous,
                                               const core::BackendConfig& config,
                                               std::string_view pool_name) {
    if (!previous)
        return {};
    for (const PoolState& pool : previous->pools)
        for (const auto& backend : pool.backends)
            if (backend->name == config.name && backend->pool == pool_name &&
                backend->configured_address == config.address &&
                backend->configured_health_address == config.health_address &&
                backend->send_proxy_v2 == config.send_proxy_v2)
                return backend;
    return {};
}

std::shared_ptr<BackendState> choose_from_pool(const PoolState& pool, std::uint64_t sequence) {
    std::shared_ptr<BackendState> selected;
    std::uint64_t selected_load = std::numeric_limits<std::uint64_t>::max();
    if (pool.backends.empty())
        return {};
    const std::size_t offset = sequence % pool.backends.size();
    for (std::size_t relative_index = 0; relative_index < pool.backends.size(); ++relative_index) {
        const auto& candidate = pool.backends[(relative_index + offset) % pool.backends.size()];
        if (!candidate->healthy.load(std::memory_order_relaxed))
            continue;
        const std::uint64_t load = candidate->active_connections.load(std::memory_order_relaxed);
        if (!selected || load < selected_load) {
            selected = candidate;
            selected_load = load;
        }
    }
    return selected;
}

bool has_compatible_source(const std::vector<net::SocketAddress>& sources,
                           const std::vector<net::SocketAddress>& destinations) {
    return std::ranges::any_of(destinations, [&sources](const net::SocketAddress& destination) {
        return std::ranges::any_of(sources, [&destination](const net::SocketAddress& source) {
            return source.family == destination.family;
        });
    });
}

} // namespace

std::shared_ptr<RoutingTable> make_routing_table(
    const core::Config& config, const std::shared_ptr<const RoutingTable>& previous) {
    auto table = std::make_shared<RoutingTable>();
    table->active_pool = config.active_pool;
    table->failover = config.failover;
    table->health = config.health;
    table->upstream_source_addresses.reserve(config.upstream_source_addresses.size());
    for (const std::string& host : config.upstream_source_addresses)
        table->upstream_source_addresses.push_back(net::resolve_numeric_bind_host(host));
    for (const core::PoolConfig& pool_config : config.pools) {
        PoolState pool{.name = pool_config.name, .backends = {}};
        for (const core::BackendConfig& backend_config : pool_config.backends) {
            auto backend = reusable_backend(previous, backend_config, pool_config.name);
            if (!backend) {
                backend = std::make_shared<BackendState>();
                backend->name = backend_config.name;
                backend->pool = pool_config.name;
                backend->configured_address = backend_config.address;
                backend->socket_addresses =
                    net::resolve_endpoints(net::parse_endpoint(backend_config.address));
                backend->configured_health_address = backend_config.health_address;
                if (!backend_config.health_address.empty())
                    backend->health_socket_addresses = net::resolve_endpoints(
                        net::parse_endpoint(backend_config.health_address));
                backend->send_proxy_v2 = backend_config.send_proxy_v2;
            }
            if (!table->upstream_source_addresses.empty() &&
                !has_compatible_source(table->upstream_source_addresses,
                                       backend->socket_addresses))
                throw core::ConfigError("backend " + pool_config.name + "/" +
                                        backend_config.name +
                                        " has no family-compatible upstream source address");
            pool.backends.push_back(std::move(backend));
        }
        table->pools.push_back(std::move(pool));
        if (pool_config.name == config.active_pool)
            table->active_pool_index = table->pools.size() - 1;
    }
    return table;
}

std::shared_ptr<BackendState> select_backend(const RoutingTable& table,
                                             std::uint64_t sequence) {
    if (table.active_pool_index < table.pools.size())
        if (auto backend = choose_from_pool(table.pools[table.active_pool_index], sequence))
            return backend;
    if (!table.failover)
        return {};
    for (std::size_t pool_index = 0; pool_index < table.pools.size(); ++pool_index) {
        if (pool_index == table.active_pool_index)
            continue;
        if (auto backend = choose_from_pool(table.pools[pool_index], sequence))
            return backend;
    }
    return {};
}

bool has_routable_backend(const RoutingTable& table) {
    const auto pool_has_healthy_backend = [](const PoolState& pool) {
        return std::ranges::any_of(pool.backends, [](const auto& backend) {
            return backend->healthy.load(std::memory_order_relaxed);
        });
    };
    if (table.active_pool_index < table.pools.size() &&
        pool_has_healthy_backend(table.pools[table.active_pool_index]))
        return true;
    if (!table.failover)
        return false;
    for (std::size_t pool_index = 0; pool_index < table.pools.size(); ++pool_index)
        if (pool_index != table.active_pool_index &&
            pool_has_healthy_backend(table.pools[pool_index]))
            return true;
    return false;
}

} // namespace erikslund::routing
