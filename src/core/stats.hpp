#pragma once
// Cache-local reactor counters with scrape-time process aggregation.

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

#include "stratum/validator.hpp"

namespace erikslund::core {

inline constexpr std::size_t kCacheLineBytes = 64;

struct alignas(kCacheLineBytes) WorkerStats {
    std::atomic<std::uint64_t> accepted_connections{0};
    std::atomic<std::uint64_t> closed_connections{0};
    std::atomic<std::uint64_t> active_connections{0};
    std::atomic<std::uint64_t> rejected_global_limit{0};
    std::atomic<std::uint64_t> rejected_global_rate{0};
    std::atomic<std::uint64_t> rejected_source_capacity{0};
    std::atomic<std::uint64_t> rejected_ip_limit{0};
    std::atomic<std::uint64_t> rejected_rate_limit{0};
    std::atomic<std::uint64_t> rejected_traffic_rate{0};
    std::atomic<std::uint64_t> rejected_queue_limit{0};
    std::atomic<std::uint64_t> rejected_tls{0};
    std::atomic<std::uint64_t> rejected_protocol{0};
    std::atomic<std::uint64_t> rejected_no_backend{0};
    std::atomic<std::uint64_t> upstream_connect_errors{0};
    std::atomic<std::uint64_t> client_bytes{0};
    std::atomic<std::uint64_t> upstream_bytes{0};
    std::atomic<std::uint64_t> events_processed{0};
    std::atomic<std::uint64_t> event_batches{0};
    std::atomic<std::uint64_t> batch_processing_nanoseconds{0};
    std::atomic<std::uint64_t> maximum_batch_processing_nanoseconds{0};
    std::atomic<std::uint64_t> tls_handshake_attempts{0};
    std::atomic<std::uint64_t> tls_handshake_successes{0};
    std::atomic<std::uint64_t> tls_handshake_nanoseconds{0};
    std::array<std::atomic<std::uint64_t>, stratum::kValidationErrorCount> protocol_errors{};

    void record_protocol_error(stratum::ValidationError error) noexcept;
    void record_event_batch(std::size_t events, std::chrono::nanoseconds processing_time) noexcept;
};

struct StatsSnapshot {
    std::uint64_t accepted_connections = 0;
    std::uint64_t closed_connections = 0;
    std::uint64_t rejected_global_limit = 0;
    std::uint64_t rejected_global_rate = 0;
    std::uint64_t rejected_source_capacity = 0;
    std::uint64_t rejected_ip_limit = 0;
    std::uint64_t rejected_rate_limit = 0;
    std::uint64_t rejected_traffic_rate = 0;
    std::uint64_t rejected_queue_limit = 0;
    std::uint64_t rejected_tls = 0;
    std::uint64_t rejected_protocol = 0;
    std::uint64_t rejected_no_backend = 0;
    std::uint64_t upstream_connect_errors = 0;
    std::uint64_t client_bytes = 0;
    std::uint64_t upstream_bytes = 0;
    std::uint64_t events_processed = 0;
    std::uint64_t event_batches = 0;
    std::uint64_t batch_processing_nanoseconds = 0;
    std::uint64_t maximum_batch_processing_nanoseconds = 0;
    std::uint64_t tls_handshake_attempts = 0;
    std::uint64_t tls_handshake_successes = 0;
    std::uint64_t tls_handshake_nanoseconds = 0;
    std::array<std::uint64_t, stratum::kValidationErrorCount> protocol_errors{};
};

class Stats {
public:
    Stats() : started_at(std::chrono::steady_clock::now()) {}

    Stats(const Stats&) = delete;
    Stats& operator=(const Stats&) = delete;

    void initialize_workers(std::size_t count);

    [[nodiscard]] WorkerStats& worker(std::size_t index) noexcept {
        return *workers_[index];
    }

    [[nodiscard]] const WorkerStats& worker(std::size_t index) const noexcept {
        return *workers_[index];
    }

    [[nodiscard]] std::size_t worker_count() const noexcept {
        return workers_.size();
    }

    [[nodiscard]] StatsSnapshot snapshot() const noexcept;
    [[nodiscard]] bool try_reserve_queued_bytes(std::size_t bytes) noexcept;
    void release_queued_bytes(std::size_t bytes) noexcept;

    std::chrono::steady_clock::time_point started_at;
    alignas(kCacheLineBytes) std::atomic<std::uint64_t> active_connections{0};
    alignas(kCacheLineBytes) std::atomic<std::uint64_t> queued_bytes{0};
    std::atomic<std::uint64_t> queued_bytes_high_water{0};
    alignas(kCacheLineBytes) std::atomic<std::uint64_t> queued_bytes_limit{
        std::numeric_limits<std::uint64_t>::max()};
    alignas(kCacheLineBytes) std::atomic<std::uint64_t> tracked_clients{0};
    alignas(kCacheLineBytes) std::atomic<std::uint64_t> io_workers{0};
    std::atomic<std::uint64_t> tls_reload_successes{0};
    std::atomic<std::uint64_t> tls_reload_failures{0};

private:
    std::vector<std::unique_ptr<WorkerStats>> workers_;
};

} // namespace erikslund::core
