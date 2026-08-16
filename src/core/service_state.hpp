#pragma once
// Atomically published configuration, route, and TLS certificate snapshots.

#include <atomic>
#include <cstdint>
#include <memory>
#include <utility>

#include "core/config.hpp"
#include "core/stats.hpp"
#include "core/tls_certificate.hpp"
#include "routing/router.hpp"

namespace erikslund::core {

struct RuntimeSnapshot {
    std::shared_ptr<const Config> config;
    std::shared_ptr<const routing::RoutingTable> routing;
};

struct ServiceState {
    void publish(std::shared_ptr<const Config> config,
                 std::shared_ptr<const routing::RoutingTable> routing) {
        const std::uint64_t replacement_queue_limit = config->limits.max_queued_bytes;
        auto replacement = std::make_shared<const RuntimeSnapshot>(
            RuntimeSnapshot{.config = std::move(config), .routing = std::move(routing)});
        // Publish process-wide ceilings before the snapshot that makes the replacement runtime
        // visible. Existing sessions deliberately retain their routing snapshot, but must obey
        // current process memory limits. Construct first so allocation failure cannot partially
        // apply a reload.
        stats.queued_bytes_limit.store(replacement_queue_limit,
                                       std::memory_order_relaxed);
        runtime.store(std::move(replacement), std::memory_order_release);
    }

    std::atomic<std::shared_ptr<const RuntimeSnapshot>> runtime;
    std::atomic<std::shared_ptr<const TlsCertificateStatuses>> tls_certificates{
        std::make_shared<const TlsCertificateStatuses>()};
    Stats stats;
};

} // namespace erikslund::core
