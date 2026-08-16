#include "core/stats.hpp"

#include <algorithm>

namespace erikslund::core {

void WorkerStats::record_protocol_error(stratum::ValidationError error) noexcept {
    rejected_protocol.fetch_add(1, std::memory_order_relaxed);
    const auto index = static_cast<std::size_t>(error);
    if (index < protocol_errors.size())
        protocol_errors[index].fetch_add(1, std::memory_order_relaxed);
}

void WorkerStats::record_event_batch(std::size_t events,
                                     std::chrono::nanoseconds processing_time) noexcept {
    const auto elapsed = static_cast<std::uint64_t>(
        std::max<std::chrono::nanoseconds::rep>(processing_time.count(), 0));
    events_processed.fetch_add(events, std::memory_order_relaxed);
    event_batches.fetch_add(1, std::memory_order_relaxed);
    batch_processing_nanoseconds.fetch_add(elapsed, std::memory_order_relaxed);
    std::uint64_t maximum =
        maximum_batch_processing_nanoseconds.load(std::memory_order_relaxed);
    while (maximum < elapsed &&
           !maximum_batch_processing_nanoseconds.compare_exchange_weak(
               maximum, elapsed, std::memory_order_relaxed, std::memory_order_relaxed)) {
    }
}

void Stats::initialize_workers(std::size_t count) {
    if (!workers_.empty())
        return;
    workers_.reserve(count);
    for (std::size_t index = 0; index < count; ++index)
        workers_.push_back(std::make_unique<WorkerStats>());
}

StatsSnapshot Stats::snapshot() const noexcept {
    StatsSnapshot output;
    for (const auto& worker_stats : workers_) {
        const auto load = [](const std::atomic<std::uint64_t>& value) {
            return value.load(std::memory_order_relaxed);
        };
        output.accepted_connections += load(worker_stats->accepted_connections);
        output.closed_connections += load(worker_stats->closed_connections);
        output.rejected_global_limit += load(worker_stats->rejected_global_limit);
        output.rejected_global_rate += load(worker_stats->rejected_global_rate);
        output.rejected_source_capacity += load(worker_stats->rejected_source_capacity);
        output.rejected_ip_limit += load(worker_stats->rejected_ip_limit);
        output.rejected_rate_limit += load(worker_stats->rejected_rate_limit);
        output.rejected_traffic_rate += load(worker_stats->rejected_traffic_rate);
        output.rejected_queue_limit += load(worker_stats->rejected_queue_limit);
        output.rejected_tls += load(worker_stats->rejected_tls);
        output.rejected_protocol += load(worker_stats->rejected_protocol);
        output.rejected_no_backend += load(worker_stats->rejected_no_backend);
        output.upstream_connect_errors += load(worker_stats->upstream_connect_errors);
        output.client_bytes += load(worker_stats->client_bytes);
        output.upstream_bytes += load(worker_stats->upstream_bytes);
        output.events_processed += load(worker_stats->events_processed);
        output.event_batches += load(worker_stats->event_batches);
        output.batch_processing_nanoseconds += load(worker_stats->batch_processing_nanoseconds);
        output.maximum_batch_processing_nanoseconds =
            std::max(output.maximum_batch_processing_nanoseconds,
                     load(worker_stats->maximum_batch_processing_nanoseconds));
        output.tls_handshake_attempts += load(worker_stats->tls_handshake_attempts);
        output.tls_handshake_successes += load(worker_stats->tls_handshake_successes);
        output.tls_handshake_nanoseconds += load(worker_stats->tls_handshake_nanoseconds);
        for (std::size_t index = 0; index < output.protocol_errors.size(); ++index)
            output.protocol_errors[index] += load(worker_stats->protocol_errors[index]);
    }
    return output;
}

bool Stats::try_reserve_queued_bytes(std::size_t bytes) noexcept {
    const std::uint64_t maximum = queued_bytes_limit.load(std::memory_order_relaxed);
    if (bytes > maximum)
        return false;
    std::uint64_t current = queued_bytes.load(std::memory_order_relaxed);
    while (current <= maximum - bytes) {
        const std::uint64_t replacement = current + bytes;
        if (!queued_bytes.compare_exchange_weak(current, replacement,
                                                std::memory_order_relaxed,
                                                std::memory_order_relaxed))
            continue;
        std::uint64_t high_water = queued_bytes_high_water.load(std::memory_order_relaxed);
        while (high_water < replacement &&
               !queued_bytes_high_water.compare_exchange_weak(
                   high_water, replacement, std::memory_order_relaxed,
                   std::memory_order_relaxed)) {
        }
        return true;
    }
    return false;
}

void Stats::release_queued_bytes(std::size_t bytes) noexcept {
    queued_bytes.fetch_sub(bytes, std::memory_order_relaxed);
}

} // namespace erikslund::core
