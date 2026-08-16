#pragma once
// Exceptions for startup configuration and operating-system failures.

#include <stdexcept>

namespace erikslund::core {

struct ConfigError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct IoError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

} // namespace erikslund::core

