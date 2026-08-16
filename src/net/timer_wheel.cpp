#include "net/timer_wheel.hpp"

#include <algorithm>
#include <utility>

namespace erikslund::net {

TimerWheel::TimerWheel(Clock::time_point now, std::size_t expected_entries)
    : current_tick_(tick_floor(now)) {
    locations_.reserve(expected_entries);
}

void TimerWheel::schedule(std::uint64_t session_id, std::uint64_t generation,
                          Clock::time_point deadline) {
    cancel(session_id);
    const std::uint64_t due_tick = std::max(tick_at_or_after(deadline), current_tick_ + 1);
    insert({.expiry = {.session_id = session_id, .generation = generation},
            .due_tick = due_tick});
}

void TimerWheel::cancel(std::uint64_t session_id) {
    const auto location = locations_.find(session_id);
    if (location == locations_.end())
        return;
    auto& bucket = buckets_[location->second.bucket];
    const std::size_t index = location->second.index;
    const std::size_t last = bucket.size() - 1;
    if (index != last) {
        bucket[index] = bucket[last];
        const auto swapped = locations_.find(bucket[index].expiry.session_id);
        if (swapped != locations_.end())
            swapped->second = {.bucket = location->second.bucket, .index = index};
    }
    bucket.pop_back();
    locations_.erase(location);
}

std::vector<TimerExpiry> TimerWheel::advance(Clock::time_point now) {
    std::vector<TimerExpiry> expired;
    const std::uint64_t target_tick = tick_floor(now);
    while (current_tick_ < target_tick) {
        ++current_tick_;
        std::vector<Entry> entries =
            std::move(buckets_[current_tick_ % kBucketCount]);
        buckets_[current_tick_ % kBucketCount].clear();
        for (Entry& entry : entries) {
            locations_.erase(entry.expiry.session_id);
            if (entry.due_tick <= current_tick_)
                expired.push_back(entry.expiry);
            else
                insert(entry);
        }
    }
    return expired;
}

void TimerWheel::insert(Entry entry) {
    const std::size_t bucket_index = entry.due_tick % kBucketCount;
    auto& bucket = buckets_[bucket_index];
    locations_[entry.expiry.session_id] =
        {.bucket = bucket_index, .index = bucket.size()};
    bucket.push_back(entry);
}

std::uint64_t TimerWheel::tick_at_or_after(Clock::time_point time) {
    const auto whole_seconds = std::chrono::time_point_cast<std::chrono::seconds>(time);
    std::uint64_t tick = static_cast<std::uint64_t>(whole_seconds.time_since_epoch().count());
    if (whole_seconds < time)
        ++tick;
    return tick;
}

std::uint64_t TimerWheel::tick_floor(Clock::time_point time) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count());
}

} // namespace erikslund::net
