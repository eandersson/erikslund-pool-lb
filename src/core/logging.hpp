#pragma once
// Thread-safe, level-gated process logging with the standard Erikslund line format.

#include <format>
#include <string_view>
#include <utility>

namespace erikslund::core::log {

enum class Level { Debug = 0, Info, Notice, Warning, Error };

void set_level(Level level);
Level level();

// Write one already-formatted line. Prefer the typed helpers below.
void write(Level level, std::string_view message);

template <class... Args>
void message(Level level, std::format_string<Args...> format, Args&&... args) {
    if (level >= log::level())
        write(level, std::format(format, std::forward<Args>(args)...));
}

template <class... Args>
void debug(std::format_string<Args...> format, Args&&... args) {
    message(Level::Debug, format, std::forward<Args>(args)...);
}

template <class... Args>
void info(std::format_string<Args...> format, Args&&... args) {
    message(Level::Info, format, std::forward<Args>(args)...);
}

template <class... Args>
void notice(std::format_string<Args...> format, Args&&... args) {
    message(Level::Notice, format, std::forward<Args>(args)...);
}

template <class... Args>
void warning(std::format_string<Args...> format, Args&&... args) {
    message(Level::Warning, format, std::forward<Args>(args)...);
}

template <class... Args>
void error(std::format_string<Args...> format, Args&&... args) {
    message(Level::Error, format, std::forward<Args>(args)...);
}

} // namespace erikslund::core::log
