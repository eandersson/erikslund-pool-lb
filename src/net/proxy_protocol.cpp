#include "net/proxy_protocol.hpp"

#include <array>
#include <cstddef>
#include <cstring>

#include <arpa/inet.h>

namespace erikslund::net {

namespace {

constexpr std::array<std::uint8_t, 12> kSignature = {
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a};

void append(ProxyV2Header& output, const void* source, std::size_t size) {
    std::memcpy(output.storage.data() + output.length, source, size);
    output.length = static_cast<std::uint8_t>(output.length + size);
}

void push(ProxyV2Header& output, std::uint8_t value) {
    output.storage[output.length++] = value;
}

void append_port(ProxyV2Header& output, std::uint16_t network_port) {
    append(output, &network_port, sizeof(network_port));
}

void append_ipv4(ProxyV2Header& output, const in_addr& source, const in_addr& destination,
                 std::uint16_t source_port, std::uint16_t destination_port) {
    push(output, 0x11); // INET, STREAM
    push(output, 0);
    push(output, 12);
    append(output, &source, sizeof(source));
    append(output, &destination, sizeof(destination));
    append_port(output, source_port);
    append_port(output, destination_port);
}

bool is_ipv4_mapped(const sockaddr_in6& address) {
    return IN6_IS_ADDR_V4MAPPED(&address.sin6_addr) != 0;
}

} // namespace

ProxyV2Header make_proxy_v2_header(const sockaddr_storage& source,
                                   const sockaddr_storage& destination) {
    ProxyV2Header output;
    append(output, kSignature.data(), kSignature.size());
    push(output, 0x21); // version 2, PROXY command
    if (source.ss_family == AF_INET && destination.ss_family == AF_INET) {
        const auto& source_v4 = reinterpret_cast<const sockaddr_in&>(source);
        const auto& destination_v4 = reinterpret_cast<const sockaddr_in&>(destination);
        append_ipv4(output, source_v4.sin_addr, destination_v4.sin_addr,
                    source_v4.sin_port, destination_v4.sin_port);
    } else if (source.ss_family == AF_INET6 && destination.ss_family == AF_INET6) {
        const auto& source_v6 = reinterpret_cast<const sockaddr_in6&>(source);
        const auto& destination_v6 = reinterpret_cast<const sockaddr_in6&>(destination);
        if (is_ipv4_mapped(source_v6) && is_ipv4_mapped(destination_v6)) {
            in_addr source_v4{};
            in_addr destination_v4{};
            std::memcpy(&source_v4, &source_v6.sin6_addr.s6_addr[12], sizeof(source_v4));
            std::memcpy(&destination_v4, &destination_v6.sin6_addr.s6_addr[12],
                        sizeof(destination_v4));
            append_ipv4(output, source_v4, destination_v4, source_v6.sin6_port,
                        destination_v6.sin6_port);
        } else {
            push(output, 0x21); // INET6, STREAM
            push(output, 0);
            push(output, 36);
            append(output, &source_v6.sin6_addr, sizeof(source_v6.sin6_addr));
            append(output, &destination_v6.sin6_addr, sizeof(destination_v6.sin6_addr));
            append_port(output, source_v6.sin6_port);
            append_port(output, destination_v6.sin6_port);
        }
    } else {
        push(output, 0x00); // UNSPEC: retain the PROXY command without a spoofable address
        push(output, 0);
        push(output, 0);
    }
    return output;
}

} // namespace erikslund::net
