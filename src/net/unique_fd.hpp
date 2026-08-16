#pragma once
// Move-only ownership for POSIX file descriptors.

#include <unistd.h>

namespace erikslund::net {

class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(int value) : value_(value) {}
    ~UniqueFd() {
        reset();
    }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept : value_(other.release()) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other)
            reset(other.release());
        return *this;
    }

    [[nodiscard]] int get() const noexcept {
        return value_;
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return value_ >= 0;
    }

    int release() noexcept {
        const int value = value_;
        value_ = -1;
        return value;
    }

    void reset(int replacement = -1) noexcept {
        if (value_ >= 0)
            ::close(value_);
        value_ = replacement;
    }

private:
    int value_ = -1;
};

} // namespace erikslund::net
