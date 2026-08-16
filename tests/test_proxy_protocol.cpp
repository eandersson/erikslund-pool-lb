#include <doctest/doctest.h>

#include <cstring>

#include <arpa/inet.h>

#include "net/proxy_protocol.hpp"

TEST_CASE("PROXY v2 encodes IPv4 client and listener addresses") {
    sockaddr_storage source{};
    sockaddr_storage destination{};
    auto& source_v4 = reinterpret_cast<sockaddr_in&>(source);
    auto& destination_v4 = reinterpret_cast<sockaddr_in&>(destination);
    source_v4.sin_family = AF_INET;
    destination_v4.sin_family = AF_INET;
    REQUIRE(inet_pton(AF_INET, "192.0.2.10", &source_v4.sin_addr) == 1);
    REQUIRE(inet_pton(AF_INET, "198.51.100.20", &destination_v4.sin_addr) == 1);
    source_v4.sin_port = htons(50'000);
    destination_v4.sin_port = htons(3'333);

    const auto header = erikslund::net::make_proxy_v2_header(source, destination);
    REQUIRE(header.size() == 28);
    CHECK(header.view().size() == header.size());
    CHECK(header[12] == 0x21);
    CHECK(header[13] == 0x11);
    CHECK(header[15] == 12);
    CHECK(header[24] == 0xc3);
    CHECK(header[25] == 0x50);
    CHECK(header[26] == 0x0d);
    CHECK(header[27] == 0x05);
}

TEST_CASE("PROXY v2 encodes native IPv6 addresses") {
    sockaddr_storage source{};
    sockaddr_storage destination{};
    auto& source_v6 = reinterpret_cast<sockaddr_in6&>(source);
    auto& destination_v6 = reinterpret_cast<sockaddr_in6&>(destination);
    source_v6.sin6_family = AF_INET6;
    destination_v6.sin6_family = AF_INET6;
    REQUIRE(inet_pton(AF_INET6, "2001:db8::10", &source_v6.sin6_addr) == 1);
    REQUIRE(inet_pton(AF_INET6, "2001:db8::20", &destination_v6.sin6_addr) == 1);
    source_v6.sin6_port = htons(50'000);
    destination_v6.sin6_port = htons(3'333);

    const auto header = erikslund::net::make_proxy_v2_header(source, destination);
    REQUIRE(header.size() == 52);
    CHECK(header[13] == 0x21);
    CHECK(header[15] == 36);
    CHECK(header[48] == 0xc3);
    CHECK(header[49] == 0x50);
    CHECK(header[50] == 0x0d);
    CHECK(header[51] == 0x05);
}

TEST_CASE("PROXY v2 normalizes IPv4-mapped IPv6 peers") {
    sockaddr_storage source{};
    sockaddr_storage destination{};
    auto& source_v6 = reinterpret_cast<sockaddr_in6&>(source);
    auto& destination_v6 = reinterpret_cast<sockaddr_in6&>(destination);
    source_v6.sin6_family = AF_INET6;
    destination_v6.sin6_family = AF_INET6;
    REQUIRE(inet_pton(AF_INET6, "::ffff:192.0.2.10", &source_v6.sin6_addr) == 1);
    REQUIRE(inet_pton(AF_INET6, "::ffff:198.51.100.20", &destination_v6.sin6_addr) == 1);
    source_v6.sin6_port = htons(50'000);
    destination_v6.sin6_port = htons(3'333);

    const auto header = erikslund::net::make_proxy_v2_header(source, destination);
    REQUIRE(header.size() == 28);
    CHECK(header[13] == 0x11);
    CHECK(header[15] == 12);
    CHECK(header[16] == 192);
    CHECK(header[17] == 0);
    CHECK(header[18] == 2);
    CHECK(header[19] == 10);
    CHECK(header[20] == 198);
    CHECK(header[21] == 51);
    CHECK(header[22] == 100);
    CHECK(header[23] == 20);
}

TEST_CASE("PROXY v2 uses an address-free frame for incompatible families") {
    sockaddr_storage source{};
    sockaddr_storage destination{};
    reinterpret_cast<sockaddr_in&>(source).sin_family = AF_INET;
    reinterpret_cast<sockaddr_in6&>(destination).sin6_family = AF_INET6;

    const auto header = erikslund::net::make_proxy_v2_header(source, destination);
    REQUIRE(header.size() == 16);
    CHECK(header[12] == 0x21);
    CHECK(header[13] == 0x00);
    CHECK(header[14] == 0);
    CHECK(header[15] == 0);
}
