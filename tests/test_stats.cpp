#include <doctest/doctest.h>

#include <chrono>
#include <memory>
#include <thread>
#include <vector>

#include "core/config.hpp"
#include "core/service_state.hpp"
#include "core/stats.hpp"

TEST_CASE("stats aggregate cache-local reactor counters") {
    erikslund::core::Stats stats;
    stats.initialize_workers(2);
    stats.worker(0).client_bytes.store(10);
    stats.worker(1).client_bytes.store(20);
    stats.worker(0).accepted_connections.store(2);
    stats.worker(1).accepted_connections.store(3);
    stats.worker(0).record_protocol_error(
        erikslund::stratum::ValidationError::InvalidJson);
    stats.worker(1).record_event_batch(7, std::chrono::nanoseconds(123));

    const auto snapshot = stats.snapshot();
    CHECK(snapshot.client_bytes == 30);
    CHECK(snapshot.accepted_connections == 5);
    CHECK(snapshot.rejected_protocol == 1);
    CHECK(snapshot.protocol_errors[static_cast<std::size_t>(
              erikslund::stratum::ValidationError::InvalidJson)] == 1);
    CHECK(snapshot.events_processed == 7);
    CHECK(snapshot.maximum_batch_processing_nanoseconds == 123);
}

TEST_CASE("stats enforce a process-wide queued-byte budget") {
    erikslund::core::Stats stats;
    stats.queued_bytes_limit.store(100);
    CHECK(stats.try_reserve_queued_bytes(60));
    CHECK_FALSE(stats.try_reserve_queued_bytes(41));
    CHECK(stats.queued_bytes.load() == 60);
    CHECK(stats.queued_bytes_high_water.load() == 60);
    stats.release_queued_bytes(20);
    CHECK(stats.try_reserve_queued_bytes(41));
    CHECK(stats.queued_bytes.load() == 81);
    CHECK(stats.queued_bytes_high_water.load() == 81);
    stats.release_queued_bytes(81);
    CHECK(stats.queued_bytes.load() == 0);
}

TEST_CASE("stats queue accounting remains bounded under concurrent reservations") {
    constexpr std::size_t kThreads = 8;
    constexpr std::size_t kReservationsPerThread = 10'000;
    erikslund::core::Stats stats;
    stats.queued_bytes_limit.store(4);

    std::vector<std::jthread> threads;
    threads.reserve(kThreads);
    for (std::size_t thread_index = 0; thread_index < kThreads; ++thread_index) {
        threads.emplace_back([&stats] {
            for (std::size_t reservation = 0; reservation < kReservationsPerThread;
                 ++reservation) {
                while (!stats.try_reserve_queued_bytes(1))
                    std::this_thread::yield();
                stats.release_queued_bytes(1);
            }
        });
    }
    threads.clear();

    CHECK(stats.queued_bytes.load() == 0);
    CHECK(stats.queued_bytes_high_water.load() <= stats.queued_bytes_limit.load());
}

TEST_CASE("runtime publication immediately replaces the process queue limit") {
    erikslund::core::ServiceState state;
    auto initial = std::make_shared<erikslund::core::Config>();
    initial->limits.max_queued_bytes = 100;
    state.publish(initial, std::make_shared<erikslund::routing::RoutingTable>());
    CHECK(state.stats.queued_bytes_limit.load() == 100);
    REQUIRE(state.stats.try_reserve_queued_bytes(80));

    auto replacement = std::make_shared<erikslund::core::Config>(*initial);
    replacement->limits.max_queued_bytes = 50;
    state.publish(replacement, std::make_shared<erikslund::routing::RoutingTable>());
    CHECK(state.stats.queued_bytes_limit.load() == 50);
    CHECK_FALSE(state.stats.try_reserve_queued_bytes(1));

    state.stats.release_queued_bytes(80);
    CHECK(state.stats.try_reserve_queued_bytes(50));
    state.stats.release_queued_bytes(50);
    CHECK(state.stats.queued_bytes.load() == 0);
}
