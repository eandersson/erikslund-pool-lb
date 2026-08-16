#pragma once
// Per-client-IP concurrent connection and token-bucket admission control.

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>

#include "core/config.hpp"
#include "net/endpoint.hpp"

namespace erikslund::net {

enum class AdmissionResult {
    Accepted,
    ConcurrentLimit,
    RateLimit,
    GlobalRateLimit,
    SourceCapacity,
};

class RateLimiter {
    struct ClientState;

public:
    using Clock = std::chrono::steady_clock;

    class Lease {
    public:
        Lease() = default;
        ~Lease();

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept;
        Lease& operator=(Lease&& other) noexcept;

        void reset() noexcept;

        [[nodiscard]] explicit operator bool() const noexcept {
            return limiter_ != nullptr;
        }

    private:
        friend class RateLimiter;

        Lease(RateLimiter& limiter, std::size_t shard_index, ClientState& state) noexcept;

        RateLimiter* limiter_ = nullptr;
        std::size_t shard_index_ = 0;
        ClientState* state_ = nullptr;
    };

    struct Admission {
        AdmissionResult result = AdmissionResult::RateLimit;
        Lease lease;
    };

    Admission acquire(const ClientKey& client_key, const core::LimitsConfig& limits);
    bool consume_traffic(const Lease& lease, std::size_t bytes, std::size_t messages,
                         const core::LimitsConfig& limits, Clock::time_point now);

    [[nodiscard]] std::size_t tracked_clients() const noexcept {
        return tracked_clients_.load(std::memory_order_relaxed);
    }

private:
    struct TokenBucket {
        double tokens = 0.0;
        std::chrono::steady_clock::time_point updated_at{};
    };

    struct ClientState {
        TokenBucket connection_bucket;
        TokenBucket message_bucket;
        TokenBucket byte_bucket;
        std::size_t active = 0;
        std::chrono::steady_clock::time_point last_seen{};
    };

    static constexpr std::size_t kShardCount = 64;

    struct Shard {
        std::mutex mutex;
        std::unordered_map<ClientKey, ClientState, ClientKeyHash> clients;
        std::chrono::steady_clock::time_point last_pruned{};
    };

    [[nodiscard]] std::size_t shard_index_for(const ClientKey& client_key) const noexcept;
    void release(std::size_t shard_index, ClientState* state) noexcept;
    void prune(Shard& shard, std::chrono::steady_clock::time_point now,
               std::chrono::seconds retention);
    bool evict_oldest_inactive(Shard& shard);
    bool reserve_tracking_slot(std::size_t maximum);
    bool consume_global_connection(std::chrono::steady_clock::time_point now,
                                   const core::LimitsConfig& limits);
    static void refill(TokenBucket& bucket, std::chrono::steady_clock::time_point now,
                       double rate_per_second, std::size_t burst);

    std::array<Shard, kShardCount> shards_;
    std::atomic<std::int64_t> global_theoretical_arrival_nanoseconds_{0};
    std::atomic<std::size_t> tracked_clients_{0};
};

} // namespace erikslund::net
