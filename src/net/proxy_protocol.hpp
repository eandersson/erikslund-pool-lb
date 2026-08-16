#pragma once
// HAProxy PROXY protocol v2 encoder for preserving the miner address upstream.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <sys/socket.h>

namespace erikslund::net {

inline constexpr std::size_t kMaximumProxyV2HeaderBytes = 52;

struct ProxyV2Header {
    std::array<std::uint8_t, kMaximumProxyV2HeaderBytes> storage{};
    std::uint8_t length = 0;

    [[nodiscard]] std::size_t size() const noexcept {
        return length;
    }

    [[nodiscard]] std::uint8_t operator[](std::size_t index) const noexcept {
        return storage[index];
    }

    [[nodiscard]] std::string_view view() const noexcept {
        return {reinterpret_cast<const char*>(storage.data()), size()};
    }
};

ProxyV2Header make_proxy_v2_header(const sockaddr_storage& source,
                                   const sockaddr_storage& destination);

} // namespace erikslund::net
