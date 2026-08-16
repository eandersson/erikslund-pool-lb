#include "core/logging.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <mutex>

namespace erikslund::core::log {

namespace {

std::atomic<Level> g_level{Level::Info};
std::mutex g_write_mutex;

const char* level_name(Level level) {
    switch (level) {
    case Level::Debug:
        return "DEBUG";
    case Level::Info:
        return "INFO";
    case Level::Notice:
        return "NOTICE";
    case Level::Warning:
        return "WARNING";
    case Level::Error:
        return "ERROR";
    }
    return "?";
}

} // namespace

void set_level(Level level) {
    g_level.store(level, std::memory_order_relaxed);
}

Level level() {
    return g_level.load(std::memory_order_relaxed);
}

void write(Level level, std::string_view message) {
    const auto now = std::chrono::system_clock::now();
    const std::time_t seconds = std::chrono::system_clock::to_time_t(now);
    std::tm local_time{};
#if defined(_WIN32)
    localtime_s(&local_time, &seconds);
#else
    localtime_r(&seconds, &local_time);
#endif
    char timestamp[32];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &local_time);
    const auto milliseconds =
        std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    const long long ms = static_cast<long long>(milliseconds.count());

    const std::scoped_lock lock(g_write_mutex);
    std::fprintf(stderr, "[%s.%03lld] %-7s %.*s\n", timestamp, ms, level_name(level),
                 static_cast<int>(message.size()), message.data());
    std::fflush(stderr);
}

} // namespace erikslund::core::log
