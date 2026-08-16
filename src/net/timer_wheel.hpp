#pragma once
// Fixed-bucket, one-second timer wheel with one cancellable entry per live session.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace erikslund::net {

struct TimerExpiry {
    std::uint64_t session_id;
    std::uint64_t generation;
};

class TimerWheel {
public:
    using Clock = std::chrono::steady_clock;
    static constexpr std::size_t kBucketCount = 4'096;

    explicit TimerWheel(Clock::time_point now, std::size_t expected_entries = 0);

    void schedule(std::uint64_t session_id, std::uint64_t generation,
                  Clock::time_point deadline);
    void cancel(std::uint64_t session_id);
    std::vector<TimerExpiry> advance(Clock::time_point now);

    [[nodiscard]] std::size_t size() const noexcept {
        return locations_.size();
    }

private:
    struct Entry {
        TimerExpiry expiry;
        std::uint64_t due_tick;
    };

    struct Location {
        std::size_t bucket;
        std::size_t index;
    };

    void insert(Entry entry);
    static std::uint64_t tick_floor(Clock::time_point time);
    static std::uint64_t tick_at_or_after(Clock::time_point time);

    std::array<std::vector<Entry>, kBucketCount> buckets_;
    std::unordered_map<std::uint64_t, Location> locations_;
    std::uint64_t current_tick_;
};

} // namespace erikslund::net
