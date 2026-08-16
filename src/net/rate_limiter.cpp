#include "net/rate_limiter.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <tuple>
#include <utility>

namespace erikslund::net {

namespace {

constexpr auto kPruneInterval = std::chrono::minutes(1);
constexpr std::int64_t kNanosecondsPerSecond = 1'000'000'000;
constexpr std::int64_t kMaximumGcraIntervalNanoseconds = 1'000'000'000'000'000'000;

std::int64_t saturating_add(std::int64_t left, std::int64_t right) noexcept {
    if (right > std::numeric_limits<std::int64_t>::max() - left)
        return std::numeric_limits<std::int64_t>::max();
    return left + right;
}

std::int64_t saturating_multiply(std::size_t left, std::int64_t right) noexcept {
    if (left > static_cast<std::size_t>(std::numeric_limits<std::int64_t>::max() / right))
        return std::numeric_limits<std::int64_t>::max();
    return static_cast<std::int64_t>(left) * right;
}

} // namespace

RateLimiter::Lease::Lease(RateLimiter& limiter, std::size_t shard_index,
                          ClientState& state) noexcept
    : limiter_(&limiter), shard_index_(shard_index), state_(&state) {}

RateLimiter::Lease::~Lease() {
    reset();
}

RateLimiter::Lease::Lease(Lease&& other) noexcept
    : limiter_(std::exchange(other.limiter_, nullptr)), shard_index_(other.shard_index_),
      state_(std::exchange(other.state_, nullptr)) {}

RateLimiter::Lease& RateLimiter::Lease::operator=(Lease&& other) noexcept {
    if (this == &other)
        return *this;
    reset();
    limiter_ = std::exchange(other.limiter_, nullptr);
    shard_index_ = other.shard_index_;
    state_ = std::exchange(other.state_, nullptr);
    return *this;
}

void RateLimiter::Lease::reset() noexcept {
    if (limiter_ != nullptr)
        limiter_->release(shard_index_, state_);
    limiter_ = nullptr;
    state_ = nullptr;
}

RateLimiter::Admission RateLimiter::acquire(const ClientKey& client_key,
                                            const core::LimitsConfig& limits) {
    const auto now = Clock::now();

    const std::size_t shard_index = shard_index_for(client_key);
    Shard& shard = shards_[shard_index];
    std::lock_guard lock(shard.mutex);
    if (shard.last_pruned == std::chrono::steady_clock::time_point{} ||
        now - shard.last_pruned >= kPruneInterval) {
        prune(shard, now, std::chrono::seconds(limits.client_state_retention_seconds));
        shard.last_pruned = now;
    }
    const bool known_client = shard.clients.contains(client_key);
    if (!known_client && !reserve_tracking_slot(limits.max_tracked_client_ips)) {
        if (!evict_oldest_inactive(shard) ||
            !reserve_tracking_slot(limits.max_tracked_client_ips))
            return {.result = AdmissionResult::SourceCapacity, .lease = {}};
    }

    decltype(shard.clients)::iterator iterator;
    bool inserted = false;
    try {
        std::tie(iterator, inserted) = shard.clients.try_emplace(client_key);
    } catch (...) {
        if (!known_client)
            tracked_clients_.fetch_sub(1, std::memory_order_relaxed);
        throw;
    }
    ClientState& state = iterator->second;
    if (inserted) {
        state.connection_bucket = {
            .tokens = static_cast<double>(limits.connection_burst_per_ip), .updated_at = now};
        state.message_bucket = {
            .tokens = static_cast<double>(limits.message_burst_per_ip), .updated_at = now};
        state.byte_bucket = {
            .tokens = static_cast<double>(limits.byte_burst_per_ip), .updated_at = now};
    }
    state.last_seen = now;
    refill(state.connection_bucket, now, limits.connections_per_second_per_ip,
           limits.connection_burst_per_ip);
    if (state.active >= limits.max_connections_per_ip)
        return {.result = AdmissionResult::ConcurrentLimit, .lease = {}};
    if (state.connection_bucket.tokens < 1.0)
        return {.result = AdmissionResult::RateLimit, .lease = {}};
    if (!consume_global_connection(now, limits)) {
        if (inserted) {
            shard.clients.erase(iterator);
            tracked_clients_.fetch_sub(1, std::memory_order_relaxed);
        }
        return {.result = AdmissionResult::GlobalRateLimit, .lease = {}};
    }
    state.connection_bucket.tokens -= 1.0;
    ++state.active;
    return {.result = AdmissionResult::Accepted,
            .lease = Lease(*this, shard_index, state)};
}

bool RateLimiter::consume_traffic(const Lease& lease, std::size_t bytes,
                                  std::size_t messages, const core::LimitsConfig& limits,
                                  Clock::time_point now) {
    if (!lease || lease.limiter_ != this)
        return false;
    Shard& shard = shards_[lease.shard_index_];
    std::lock_guard lock(shard.mutex);
    ClientState& state = *lease.state_;
    state.last_seen = now;
    refill(state.byte_bucket, now, limits.bytes_per_second_per_ip,
           limits.byte_burst_per_ip);
    refill(state.message_bucket, now, limits.messages_per_second_per_ip,
           limits.message_burst_per_ip);
    if (state.byte_bucket.tokens < static_cast<double>(bytes) ||
        state.message_bucket.tokens < static_cast<double>(messages))
        return false;
    state.byte_bucket.tokens -= static_cast<double>(bytes);
    state.message_bucket.tokens -= static_cast<double>(messages);
    return true;
}

void RateLimiter::release(std::size_t shard_index, ClientState* state) noexcept {
    Shard& shard = shards_[shard_index];
    std::lock_guard lock(shard.mutex);
    if (state->active > 0)
        --state->active;
}

std::size_t RateLimiter::shard_index_for(const ClientKey& client_key) const noexcept {
    return ClientKeyHash{}(client_key) % shards_.size();
}

void RateLimiter::prune(Shard& shard, std::chrono::steady_clock::time_point now,
                        std::chrono::seconds retention) {
    const std::size_t before = shard.clients.size();
    std::erase_if(shard.clients, [now, retention](const auto& entry) {
        return entry.second.active == 0 && now - entry.second.last_seen > retention;
    });
    tracked_clients_.fetch_sub(before - shard.clients.size(), std::memory_order_relaxed);
}

bool RateLimiter::evict_oldest_inactive(Shard& shard) {
    auto oldest = shard.clients.end();
    for (auto iterator = shard.clients.begin(); iterator != shard.clients.end(); ++iterator) {
        if (iterator->second.active != 0)
            continue;
        if (oldest == shard.clients.end() ||
            iterator->second.last_seen < oldest->second.last_seen)
            oldest = iterator;
    }
    if (oldest == shard.clients.end())
        return false;
    shard.clients.erase(oldest);
    tracked_clients_.fetch_sub(1, std::memory_order_relaxed);
    return true;
}

bool RateLimiter::reserve_tracking_slot(std::size_t maximum) {
    std::size_t current = tracked_clients_.load(std::memory_order_relaxed);
    while (current < maximum) {
        if (tracked_clients_.compare_exchange_weak(current, current + 1,
                                                   std::memory_order_relaxed))
            return true;
    }
    return false;
}

bool RateLimiter::consume_global_connection(std::chrono::steady_clock::time_point now,
                                            const core::LimitsConfig& limits) {
    const double interval_value =
        static_cast<double>(kNanosecondsPerSecond) / limits.global_connections_per_second;
    const auto interval = static_cast<std::int64_t>(
        std::clamp(std::ceil(interval_value), 1.0,
                   static_cast<double>(kMaximumGcraIntervalNanoseconds)));
    const std::int64_t tolerance =
        saturating_multiply(limits.global_connection_burst - 1, interval);
    const std::int64_t now_nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    std::int64_t theoretical_arrival =
        global_theoretical_arrival_nanoseconds_.load(std::memory_order_relaxed);
    while (true) {
        const std::int64_t base = std::max(theoretical_arrival, now_nanoseconds);
        if (base - now_nanoseconds > tolerance)
            return false;
        const std::int64_t replacement = saturating_add(base, interval);
        if (global_theoretical_arrival_nanoseconds_.compare_exchange_weak(
                theoretical_arrival, replacement, std::memory_order_relaxed,
                std::memory_order_relaxed))
            return true;
    }
}

void RateLimiter::refill(TokenBucket& bucket, std::chrono::steady_clock::time_point now,
                         double rate_per_second, std::size_t burst) {
    if (bucket.updated_at == std::chrono::steady_clock::time_point{}) {
        bucket.tokens = static_cast<double>(burst);
    } else {
        const double elapsed = std::chrono::duration<double>(now - bucket.updated_at).count();
        bucket.tokens = std::min(static_cast<double>(burst),
                                 bucket.tokens + elapsed * rate_per_second);
    }
    bucket.updated_at = now;
}

} // namespace erikslund::net
