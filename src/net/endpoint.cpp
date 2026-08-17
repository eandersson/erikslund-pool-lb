#include "net/endpoint.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <memory>
#include <string_view>

#include <arpa/inet.h>
#include <netdb.h>

#include "core/errors.hpp"

namespace erikslund::net {

namespace {

constexpr std::uint64_t kFnvOffsetBasis = 1'469'598'103'934'665'603ULL;
constexpr std::uint64_t kFnvPrime = 1'099'511'628'211ULL;
constexpr std::uint8_t kIpv4PrefixBits = 32;

void hash_byte(std::uint64_t& hash, std::uint8_t byte) noexcept {
    hash ^= byte;
    hash *= kFnvPrime;
}

std::vector<SocketAddress> resolve_addresses(std::string_view host, std::uint16_t port,
                                             int flags) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = flags;

    addrinfo* raw_results = nullptr;
    const std::string host_text(host);
    const std::string port_text = std::to_string(port);
    const int error =
        ::getaddrinfo(host_text.c_str(), port_text.c_str(), &hints, &raw_results);
    if (error != 0)
        throw core::ConfigError("cannot resolve " + host_text + ": " + gai_strerror(error));

    const std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> results(raw_results,
                                                                      ::freeaddrinfo);
    std::vector<SocketAddress> addresses;
    for (const addrinfo* entry = results.get(); entry != nullptr; entry = entry->ai_next) {
        if ((entry->ai_family != AF_INET && entry->ai_family != AF_INET6) ||
            entry->ai_addrlen > sizeof(sockaddr_storage))
            continue;
        SocketAddress address;
        std::memcpy(&address.value, entry->ai_addr, entry->ai_addrlen);
        address.length = static_cast<socklen_t>(entry->ai_addrlen);
        address.family = entry->ai_family;
        const bool duplicate = std::ranges::any_of(
            addresses, [&address](const SocketAddress& prior) { return same_address(prior, address); });
        if (!duplicate)
            addresses.push_back(address);
    }
    if (addresses.empty())
        throw core::ConfigError("no usable address for " + host_text);
    return addresses;
}

} // namespace

Endpoint parse_endpoint(const std::string& address) {
    std::string_view host;
    std::string_view port_text;
    if (address.starts_with('[')) {
        const std::size_t close = address.find(']');
        if (close == std::string::npos || close + 1 >= address.size() ||
            address[close + 1] != ':')
            throw core::ConfigError("invalid bracketed endpoint: " + address);
        host = std::string_view(address).substr(1, close - 1);
        port_text = std::string_view(address).substr(close + 2);
    } else {
        const std::size_t colon = address.rfind(':');
        if (colon == std::string::npos)
            throw core::ConfigError("endpoint has no port: " + address);
        if (address.find(':') != colon)
            throw core::ConfigError("IPv6 endpoints must use brackets: " + address);
        host = std::string_view(address).substr(0, colon);
        port_text = std::string_view(address).substr(colon + 1);
    }
    if (host.empty() || port_text.empty())
        throw core::ConfigError("endpoint requires a host and port: " + address);

    const std::string port_string(port_text);
    unsigned int port = 0;
    const char* const end = port_string.data() + port_string.size();
    const auto [pointer, error] = std::from_chars(port_string.data(), end, port);
    if (error != std::errc{} || pointer != end || port == 0 || port > 65'535)
        throw core::ConfigError("invalid endpoint port: " + address);
    return {.host = std::string(host), .port = static_cast<std::uint16_t>(port)};
}

std::vector<SocketAddress> resolve_endpoints(const Endpoint& endpoint, bool passive) {
    return resolve_addresses(endpoint.host, endpoint.port, passive ? AI_PASSIVE : 0);
}

bool same_address(const SocketAddress& left, const SocketAddress& right) noexcept {
    // sockaddr_storage is padded well past the bytes any family uses; only the resolved prefix
    // carries meaning, and resolve_addresses zero-fills the rest.
    return left.family == right.family && left.length == right.length &&
           std::memcmp(&left.value, &right.value, left.length) == 0;
}

bool same_addresses(const std::vector<SocketAddress>& left,
                    const std::vector<SocketAddress>& right) {
    // Resolvers commonly rotate records between queries, so compare as a set: only a genuine
    // change of destination should count as a different address list.
    return left.size() == right.size() && std::ranges::is_permutation(left, right, same_address);
}

SocketAddress resolve_numeric_bind_host(std::string_view host) {
    SocketAddress address =
        resolve_addresses(host, 0, AI_NUMERICHOST | AI_NUMERICSERV).front();
    bool usable = false;
    if (address.family == AF_INET) {
        const auto& value = reinterpret_cast<const sockaddr_in&>(address.value);
        const std::uint32_t host_order_address = ntohl(value.sin_addr.s_addr);
        usable = host_order_address != INADDR_ANY &&
                 host_order_address != INADDR_BROADCAST &&
                 IN_MULTICAST(host_order_address) == 0;
    } else if (address.family == AF_INET6) {
        const auto& value = reinterpret_cast<const sockaddr_in6&>(address.value);
        usable = IN6_IS_ADDR_UNSPECIFIED(&value.sin6_addr) == 0 &&
                 IN6_IS_ADDR_MULTICAST(&value.sin6_addr) == 0;
    }
    if (!usable)
        throw core::ConfigError("unusable outbound source address: " + std::string(host));
    return address;
}

std::string address_host(const sockaddr_storage& address) {
    char host[INET6_ADDRSTRLEN]{};
    const void* source = nullptr;
    if (address.ss_family == AF_INET)
        source = &reinterpret_cast<const sockaddr_in*>(&address)->sin_addr;
    else if (address.ss_family == AF_INET6)
        source = &reinterpret_cast<const sockaddr_in6*>(&address)->sin6_addr;
    else
        return "unknown";
    if (::inet_ntop(address.ss_family, source, host, sizeof(host)) == nullptr)
        return "unknown";
    return host;
}

std::size_t ClientKeyHash::operator()(const ClientKey& key) const noexcept {
    std::uint64_t hash = kFnvOffsetBasis;
    hash_byte(hash, static_cast<std::uint8_t>(key.family));
    hash_byte(hash, key.prefix_bits);
    const std::size_t address_bytes =
        key.family == ClientAddressFamily::Ipv4 ? 4 : key.address.size();
    for (std::size_t index = 0; index < address_bytes; ++index)
        hash_byte(hash, key.address[index]);
    return static_cast<std::size_t>(hash);
}

ClientKey client_rate_limit_key(const sockaddr_storage& address, int ipv6_prefix_bits) {
    ClientKey key;
    if (address.ss_family == AF_INET) {
        const auto& address_v4 = reinterpret_cast<const sockaddr_in&>(address);
        std::memcpy(key.address.data(), &address_v4.sin_addr, sizeof(address_v4.sin_addr));
        key.prefix_bits = kIpv4PrefixBits;
        key.family = ClientAddressFamily::Ipv4;
        return key;
    }
    if (address.ss_family != AF_INET6)
        return key;

    const auto& address_v6 = reinterpret_cast<const sockaddr_in6&>(address);
    if (IN6_IS_ADDR_V4MAPPED(&address_v6.sin6_addr) != 0) {
        std::memcpy(key.address.data(), &address_v6.sin6_addr.s6_addr[12],
                    sizeof(in_addr));
        key.prefix_bits = kIpv4PrefixBits;
        key.family = ClientAddressFamily::Ipv4;
        return key;
    }

    std::memcpy(key.address.data(), &address_v6.sin6_addr, key.address.size());
    const std::size_t complete_bytes = static_cast<std::size_t>(ipv6_prefix_bits / 8);
    const int remaining_bits = ipv6_prefix_bits % 8;
    std::size_t clear_from = complete_bytes;
    if (remaining_bits != 0) {
        const auto mask = static_cast<std::uint8_t>(0xffU << (8 - remaining_bits));
        key.address[complete_bytes] &= mask;
        clear_from = complete_bytes + 1;
    }
    std::fill(key.address.begin() + static_cast<std::ptrdiff_t>(clear_from),
              key.address.end(), 0);
    key.prefix_bits = static_cast<std::uint8_t>(ipv6_prefix_bits);
    key.family = ClientAddressFamily::Ipv6;
    return key;
}

std::string client_rate_limit_key_text(const ClientKey& key) {
    if (key.family == ClientAddressFamily::Unknown)
        return "unknown";
    char host[INET6_ADDRSTRLEN]{};
    const int family = key.family == ClientAddressFamily::Ipv4 ? AF_INET : AF_INET6;
    if (::inet_ntop(family, key.address.data(), host, sizeof(host)) == nullptr)
        return "unknown";
    if (key.family == ClientAddressFamily::Ipv4)
        return "v4:" + std::string(host);
    return "v6:" + std::string(host) + "/" + std::to_string(key.prefix_bits);
}

} // namespace erikslund::net
