#include <doctest/doctest.h>

#include <cstddef>
#include <cstdint>
#include <utility>

#include <arpa/inet.h>

#include "net/endpoint.hpp"
#include "net/rate_limiter.hpp"

using erikslund::net::AdmissionResult;
using erikslund::net::RateLimiter;

namespace {

erikslund::core::LimitsConfig test_limits() {
    erikslund::core::LimitsConfig limits;
    limits.max_connections_per_ip = 1;
    limits.connections_per_second_per_ip = 100.0;
    limits.connection_burst_per_ip = 10;
    limits.global_connections_per_second = 1'000.0;
    limits.global_connection_burst = 1'000;
    limits.max_tracked_client_ips = 100;
    limits.messages_per_second_per_ip = 0.001;
    limits.message_burst_per_ip = 1;
    limits.bytes_per_second_per_ip = 1.0;
    limits.byte_burst_per_ip = 64;
    return limits;
}

erikslund::net::ClientKey client_key(std::uint8_t final_octet) {
    sockaddr_storage address{};
    auto& ipv4 = reinterpret_cast<sockaddr_in&>(address);
    ipv4.sin_family = AF_INET;
    ipv4.sin_addr.s_addr = htonl(0xc0000200U | final_octet);
    return erikslund::net::client_rate_limit_key(address, 64);
}

} // namespace

TEST_CASE("rate limiter enforces and releases the concurrent IP cap") {
    RateLimiter limiter;
    const auto limits = test_limits();
    auto first = limiter.acquire(client_key(1), limits);
    CHECK(first.result == AdmissionResult::Accepted);
    CHECK(limiter.acquire(client_key(1), limits).result == AdmissionResult::ConcurrentLimit);
    first.lease.reset();
    CHECK(limiter.acquire(client_key(1), limits).result == AdmissionResult::Accepted);
}

TEST_CASE("rate limiter isolates token buckets by client IP") {
    RateLimiter limiter;
    auto limits = test_limits();
    limits.max_connections_per_ip = 10;
    limits.connections_per_second_per_ip = 0.001;
    limits.connection_burst_per_ip = 1;
    auto first = limiter.acquire(client_key(1), limits);
    CHECK(first.result == AdmissionResult::Accepted);
    first.lease.reset();
    CHECK(limiter.acquire(client_key(1), limits).result == AdmissionResult::RateLimit);
    CHECK(limiter.acquire(client_key(2), limits).result == AdmissionResult::Accepted);
}

TEST_CASE("rate limiter enforces a process-wide admission budget before source allocation") {
    RateLimiter limiter;
    auto limits = test_limits();
    limits.global_connections_per_second = 0.001;
    limits.global_connection_burst = 1;
    CHECK(limiter.acquire(client_key(1), limits).result == AdmissionResult::Accepted);
    CHECK(limiter.acquire(client_key(2), limits).result == AdmissionResult::GlobalRateLimit);
    CHECK(limiter.tracked_clients() == 1);
}

TEST_CASE("source rejection does not drain the process-wide admission budget") {
    RateLimiter limiter;
    auto limits = test_limits();
    limits.max_connections_per_ip = 1;
    limits.global_connections_per_second = 0.001;
    limits.global_connection_burst = 2;
    auto first = limiter.acquire(client_key(1), limits);
    REQUIRE(first.result == AdmissionResult::Accepted);
    CHECK(limiter.acquire(client_key(1), limits).result == AdmissionResult::ConcurrentLimit);
    CHECK(limiter.acquire(client_key(2), limits).result == AdmissionResult::Accepted);
}

TEST_CASE("rate limiter bounds tracked source state") {
    RateLimiter limiter;
    auto limits = test_limits();
    limits.max_tracked_client_ips = 1;
    auto first = limiter.acquire(client_key(1), limits);
    CHECK(first.result == AdmissionResult::Accepted);
    CHECK(limiter.acquire(client_key(2), limits).result == AdmissionResult::SourceCapacity);
    CHECK(limiter.tracked_clients() == 1);
}

TEST_CASE("rate limiter applies ongoing message and byte budgets across sessions") {
    RateLimiter limiter;
    auto limits = test_limits();
    auto admission = limiter.acquire(client_key(1), limits);
    REQUIRE(admission.result == AdmissionResult::Accepted);
    CHECK(limiter.consume_traffic(admission.lease, 32, 1, limits, RateLimiter::Clock::now()));
    CHECK_FALSE(
        limiter.consume_traffic(admission.lease, 1, 1, limits, RateLimiter::Clock::now()));
    CHECK_FALSE(
        limiter.consume_traffic(admission.lease, 33, 0, limits, RateLimiter::Clock::now()));
}

TEST_CASE("admission leases remain valid while the source table rehashes") {
    RateLimiter limiter;
    auto limits = test_limits();
    limits.max_connections_per_ip = 512;
    limits.max_tracked_client_ips = 512;
    limits.global_connection_burst = 512;
    limits.connection_burst_per_ip = 512;
    auto retained = limiter.acquire(client_key(1), limits);
    REQUIRE(retained.result == AdmissionResult::Accepted);
    for (std::uint16_t index = 2; index < 250; ++index) {
        auto transient = limiter.acquire(client_key(static_cast<std::uint8_t>(index)), limits);
        CHECK(transient.result == AdmissionResult::Accepted);
    }
    CHECK(limiter.consume_traffic(retained.lease, 1, 0, limits, RateLimiter::Clock::now()));
}

TEST_CASE("moved admission leases release their source slot exactly once") {
    RateLimiter limiter;
    const auto limits = test_limits();
    {
        auto admission = limiter.acquire(client_key(1), limits);
        REQUIRE(admission.result == AdmissionResult::Accepted);
        RateLimiter::Lease retained = std::move(admission.lease);
        CHECK(retained);
        CHECK_FALSE(admission.lease);
        CHECK(limiter.acquire(client_key(1), limits).result ==
              AdmissionResult::ConcurrentLimit);
    }
    CHECK(limiter.acquire(client_key(1), limits).result == AdmissionResult::Accepted);
}

TEST_CASE("active admission state is never evicted at source capacity") {
    constexpr std::size_t kRateLimiterShardCount = 64;
    RateLimiter limiter;
    auto limits = test_limits();
    limits.max_tracked_client_ips = 1;
    const auto retained_key = client_key(1);
    const auto replacement_key = client_key(65);
    REQUIRE(erikslund::net::ClientKeyHash{}(retained_key) % kRateLimiterShardCount ==
            erikslund::net::ClientKeyHash{}(replacement_key) % kRateLimiterShardCount);
    auto retained = limiter.acquire(retained_key, limits);
    REQUIRE(retained.result == AdmissionResult::Accepted);
    CHECK(limiter.acquire(replacement_key, limits).result ==
          AdmissionResult::SourceCapacity);
    retained.lease.reset();
    CHECK(limiter.acquire(replacement_key, limits).result == AdmissionResult::Accepted);
}

TEST_CASE("traffic accounting rejects a lease owned by another limiter") {
    RateLimiter owner;
    RateLimiter unrelated;
    const auto limits = test_limits();
    auto admission = owner.acquire(client_key(1), limits);
    REQUIRE(admission.result == AdmissionResult::Accepted);
    CHECK_FALSE(unrelated.consume_traffic(
        admission.lease, 1, 0, limits, RateLimiter::Clock::now()));
    CHECK(owner.consume_traffic(
        admission.lease, 1, 0, limits, RateLimiter::Clock::now()));
}
