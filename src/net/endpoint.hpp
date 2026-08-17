#pragma once
// Host-and-port parsing plus resolved socket addresses.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <sys/socket.h>

namespace erikslund::net {

struct Endpoint {
    std::string host;
    std::uint16_t port;
};

struct SocketAddress {
    sockaddr_storage value{};
    socklen_t length = 0;
    int family = AF_UNSPEC;
};

enum class ClientAddressFamily : std::uint8_t {
    Unknown,
    Ipv4,
    Ipv6,
};

struct ClientKey {
    std::array<std::uint8_t, 16> address{};
    std::uint8_t prefix_bits = 0;
    ClientAddressFamily family = ClientAddressFamily::Unknown;

    bool operator==(const ClientKey&) const = default;
};

struct ClientKeyHash {
    [[nodiscard]] std::size_t operator()(const ClientKey& key) const noexcept;
};

Endpoint parse_endpoint(const std::string& address);
std::vector<SocketAddress> resolve_endpoints(const Endpoint& endpoint, bool passive = false);
[[nodiscard]] bool same_address(const SocketAddress& left, const SocketAddress& right) noexcept;
[[nodiscard]] bool same_addresses(const std::vector<SocketAddress>& left,
                                  const std::vector<SocketAddress>& right);
SocketAddress resolve_numeric_bind_host(std::string_view host);
std::string address_host(const sockaddr_storage& address);
ClientKey client_rate_limit_key(const sockaddr_storage& address, int ipv6_prefix_bits);
std::string client_rate_limit_key_text(const ClientKey& key);

} // namespace erikslund::net
