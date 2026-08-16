#pragma once
// Lazily allocated relay queue with bounded retained capacity after bursts drain.

#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

namespace erikslund::net {

inline constexpr std::size_t kMaximumRetainedBufferBytes = 4'096;

inline void release_oversized_string(std::string& value) {
    if (value.capacity() > kMaximumRetainedBufferBytes)
        std::string(value).swap(value);
}

class PendingBuffer {
public:
    [[nodiscard]] bool empty() const noexcept {
        return offset_ == data_.size();
    }

    [[nodiscard]] std::size_t size() const noexcept {
        return data_.size() - offset_;
    }

    [[nodiscard]] std::size_t capacity() const noexcept {
        return data_.capacity();
    }

    [[nodiscard]] const char* data() const noexcept {
        return data_.data() + offset_;
    }

    void append(std::string_view bytes) {
        compact_if_needed();
        data_.append(bytes);
    }

    void prepend(std::string_view bytes) {
        if (bytes.empty())
            return;
        if (offset_ >= bytes.size()) {
            offset_ -= bytes.size();
            std::memcpy(data_.data() + offset_, bytes.data(), bytes.size());
            return;
        }
        std::string replacement;
        replacement.reserve(bytes.size() + size());
        replacement.append(bytes);
        replacement.append(data(), size());
        data_ = std::move(replacement);
        offset_ = 0;
    }

    void consume(std::size_t count) {
        if (count < size()) {
            offset_ += count;
            return;
        }
        data_.clear();
        offset_ = 0;
        release_oversized_string(data_);
    }

private:
    void compact_if_needed() {
        if (offset_ > 0 &&
            (offset_ >= data_.size() / 2 || offset_ > kMaximumRetainedBufferBytes)) {
            data_.erase(0, offset_);
            offset_ = 0;
        }
    }

    std::string data_;
    std::size_t offset_ = 0;
};

} // namespace erikslund::net
