#include <doctest/doctest.h>

#include <vector>

#include <arpa/inet.h>

#include "core/errors.hpp"
#include "net/endpoint.hpp"

namespace {

sockaddr_storage ipv4_address(const char* text) {
    sockaddr_storage address{};
    auto& value = reinterpret_cast<sockaddr_in&>(address);
    value.sin_family = AF_INET;
    REQUIRE(::inet_pton(AF_INET, text, &value.sin_addr) == 1);
    return address;
}

sockaddr_storage ipv6_address(const char* text) {
    sockaddr_storage address{};
    auto& value = reinterpret_cast<sockaddr_in6&>(address);
    value.sin6_family = AF_INET6;
    REQUIRE(::inet_pton(AF_INET6, text, &value.sin6_addr) == 1);
    return address;
}

} // namespace

TEST_CASE("endpoint parser handles hostnames, IPv4, and bracketed IPv6") {
    const auto hostname = erikslund::net::parse_endpoint("pool.internal:3333");
    CHECK(hostname.host == "pool.internal");
    CHECK(hostname.port == 3'333);

    const auto ipv6 = erikslund::net::parse_endpoint("[2001:db8::1]:443");
    CHECK(ipv6.host == "2001:db8::1");
    CHECK(ipv6.port == 443);
}

TEST_CASE("endpoint parser rejects ambiguous and invalid addresses") {
    CHECK_THROWS_AS(erikslund::net::parse_endpoint("pool.internal"),
                    erikslund::core::ConfigError);
    CHECK_THROWS_AS(erikslund::net::parse_endpoint("pool.internal:0"),
                    erikslund::core::ConfigError);
    CHECK_THROWS_AS(erikslund::net::parse_endpoint("pool.internal:65536"),
                    erikslund::core::ConfigError);
    CHECK_THROWS_AS(erikslund::net::parse_endpoint("2001:db8::1:3333"),
                    erikslund::core::ConfigError);
}

TEST_CASE("endpoint resolver retains every usable result") {
    const auto numeric =
        erikslund::net::resolve_endpoints(erikslund::net::parse_endpoint("127.0.0.1:3333"));
    REQUIRE(numeric.size() == 1);
    CHECK(numeric.front().family == AF_INET);

    const auto localhost =
        erikslund::net::resolve_endpoints(erikslund::net::parse_endpoint("localhost:3333"));
    CHECK_FALSE(localhost.empty());
    for (const auto& address : localhost)
        CHECK((address.family == AF_INET || address.family == AF_INET6));
}

TEST_CASE("address comparison distinguishes host, port, and family") {
    using erikslund::net::parse_endpoint;
    using erikslund::net::resolve_endpoints;
    using erikslund::net::same_address;

    const auto address = resolve_endpoints(parse_endpoint("127.0.0.1:13333")).front();
    CHECK(same_address(address, resolve_endpoints(parse_endpoint("127.0.0.1:13333")).front()));
    CHECK_FALSE(
        same_address(address, resolve_endpoints(parse_endpoint("127.0.0.1:13334")).front()));
    CHECK_FALSE(
        same_address(address, resolve_endpoints(parse_endpoint("127.0.0.2:13333")).front()));
    CHECK_FALSE(same_address(address, resolve_endpoints(parse_endpoint("[::1]:13333")).front()));
}

TEST_CASE("address list comparison ignores resolver record order") {
    using erikslund::net::parse_endpoint;
    using erikslund::net::resolve_endpoints;
    using erikslund::net::same_addresses;
    using erikslund::net::SocketAddress;

    const SocketAddress first = resolve_endpoints(parse_endpoint("127.0.0.1:13333")).front();
    const SocketAddress second = resolve_endpoints(parse_endpoint("127.0.0.2:13333")).front();
    const std::vector<SocketAddress> original{first, second};
    const std::vector<SocketAddress> same_order{first, second};
    const std::vector<SocketAddress> rotated{second, first};
    const std::vector<SocketAddress> shorter{first};
    const std::vector<SocketAddress> duplicated{first, first};
    const std::vector<SocketAddress> empty;

    CHECK(same_addresses(original, same_order));
    CHECK(same_addresses(original, rotated));
    CHECK_FALSE(same_addresses(original, shorter));
    CHECK_FALSE(same_addresses(original, duplicated));
    CHECK(same_addresses(empty, empty));
}

TEST_CASE("numeric bind resolver creates port-zero source addresses") {
    const auto ipv4 = erikslund::net::resolve_numeric_bind_host("127.0.0.2");
    REQUIRE(ipv4.family == AF_INET);
    CHECK(ntohs(reinterpret_cast<const sockaddr_in&>(ipv4.value).sin_port) == 0);

    const auto ipv6 = erikslund::net::resolve_numeric_bind_host("::1");
    REQUIRE(ipv6.family == AF_INET6);
    CHECK(ntohs(reinterpret_cast<const sockaddr_in6&>(ipv6.value).sin6_port) == 0);
}

TEST_CASE("numeric bind resolver rejects names and unusable source addresses") {
    using erikslund::core::ConfigError;
    using erikslund::net::resolve_numeric_bind_host;

    CHECK_THROWS_AS(resolve_numeric_bind_host("localhost"), ConfigError);
    CHECK_THROWS_AS(resolve_numeric_bind_host("0.0.0.0"), ConfigError);
    CHECK_THROWS_AS(resolve_numeric_bind_host("224.0.0.1"), ConfigError);
    CHECK_THROWS_AS(resolve_numeric_bind_host("255.255.255.255"), ConfigError);
    CHECK_THROWS_AS(resolve_numeric_bind_host("::"), ConfigError);
    CHECK_THROWS_AS(resolve_numeric_bind_host("ff02::1"), ConfigError);
}

TEST_CASE("rate limit keys aggregate IPv6 prefixes and normalize mapped IPv4") {
    using erikslund::net::client_rate_limit_key;
    using erikslund::net::client_rate_limit_key_text;

    const auto first = ipv6_address("2001:db8:42:7::1");
    const auto second = ipv6_address("2001:db8:42:7:ffff::2");
    CHECK(client_rate_limit_key(first, 64) == client_rate_limit_key(second, 64));
    CHECK(client_rate_limit_key(first, 128) != client_rate_limit_key(second, 128));
    CHECK(client_rate_limit_key_text(client_rate_limit_key(first, 64)) ==
          "v6:2001:db8:42:7::/64");

    const auto mapped = ipv6_address("::ffff:192.0.2.7");
    CHECK(client_rate_limit_key(mapped, 64) ==
          client_rate_limit_key(ipv4_address("192.0.2.7"), 64));
}

TEST_CASE("rate limit key hashes normalized addresses consistently") {
    const auto first = ipv6_address("2001:db8:42:7::1");
    const auto second = ipv6_address("2001:db8:42:7:ffff::2");
    const auto first_key = erikslund::net::client_rate_limit_key(first, 64);
    const auto second_key = erikslund::net::client_rate_limit_key(second, 64);
    CHECK(erikslund::net::ClientKeyHash{}(first_key) ==
          erikslund::net::ClientKeyHash{}(second_key));
}
