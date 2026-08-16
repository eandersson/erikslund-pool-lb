#include <doctest/doctest.h>

#include <string>
#include <string_view>

#include "core/config.hpp"
#include "core/errors.hpp"

namespace {

constexpr std::string_view kMinimalConfig = R"(
listeners:
  - name: sv1
    address: "127.0.0.1:3333"
pools:
  - name: primary
    backends:
      - name: pool-a
        address: "127.0.0.1:13333"
active_pool: primary
)";

} // namespace

TEST_CASE("configuration applies safe defaults to a minimal topology") {
    const auto config = erikslund::core::Config::from_string(std::string(kMinimalConfig));
    REQUIRE(config.listeners.size() == 1);
    REQUIRE(config.pools.size() == 1);
    CHECK(config.listeners.front().tls == false);
    CHECK(config.pools.front().backends.front().send_proxy_v2 == true);
    CHECK(config.failover == true);
    CHECK(config.upstream_source_addresses.empty());
    CHECK(config.api_address == "127.0.0.1:7778");
    CHECK(config.io_workers == 0);
    CHECK(config.limits.max_connections == 100'000);
    CHECK(config.limits.global_connections_per_second == 5'000.0);
    CHECK(config.limits.ipv6_prefix_bits == 64);
    CHECK(config.limits.max_tracked_client_ips == 262'144);
    CHECK(config.limits.max_messages_per_ready_event == 256);
    CHECK(config.limits.max_queued_bytes == 268'435'456);
}

TEST_CASE("configuration reads hot-reloadable upstream source addresses") {
    const std::string text = std::string(kMinimalConfig) + R"(
upstream_source_addresses:
  - "192.0.2.10"
  - "2001:db8::10"
)";
    const auto config = erikslund::core::Config::from_string(text);
    CHECK(config.upstream_source_addresses ==
          std::vector<std::string>{"192.0.2.10", "2001:db8::10"});

    auto replacement = config;
    replacement.upstream_source_addresses = {"192.0.2.11"};
    CHECK(config.restart_required_changes(replacement).empty());
}

TEST_CASE("configuration validates bounded unique numeric upstream source addresses") {
    const auto rejected = [](std::string_view addresses) {
        return erikslund::core::Config::from_string(
            std::string(kMinimalConfig) + "upstream_source_addresses:\n" +
            std::string(addresses));
    };

    CHECK_THROWS_WITH_AS(rejected("  - \"\"\n"),
                         "upstream_source_addresses entries must not be empty",
                         erikslund::core::ConfigError);
    CHECK_THROWS_AS(rejected("  - pool.example.com\n"), erikslund::core::ConfigError);
    CHECK_THROWS_AS(rejected("  - \"192.0.2.10:3333\"\n"),
                    erikslund::core::ConfigError);
    CHECK_THROWS_AS(rejected("  - \"[2001:db8::10]\"\n"),
                    erikslund::core::ConfigError);
    CHECK_THROWS_AS(rejected("  - 192.0.2.10\n  - 192.0.2.10\n"),
                    erikslund::core::ConfigError);
    CHECK_THROWS_AS(
        rejected("  - 2001:db8::1\n  - 2001:0db8:0:0:0:0:0:1\n"),
        erikslund::core::ConfigError);

    std::string too_many;
    for (std::size_t index = 0;
         index <= erikslund::core::kMaximumUpstreamSourceAddresses; ++index)
        too_many += "  - 192.0.2." + std::to_string(index + 1) + '\n';
    CHECK_THROWS_AS(rejected(too_many), erikslund::core::ConfigError);
}

TEST_CASE("configuration keeps the process queue budget above one connection buffer") {
    const std::string text = std::string(kMinimalConfig) + R"(limits:
  max_line_bytes: 1024
  max_buffer_bytes: 4096
  max_queued_bytes: 2048
)";
    CHECK_THROWS_WITH_AS(erikslund::core::Config::from_string(text),
                         "limits.max_queued_bytes must be at least limits.max_buffer_bytes",
                         erikslund::core::ConfigError);
}

TEST_CASE("configuration bounds IPv6 source aggregation") {
    const std::string text =
        std::string(kMinimalConfig) + "limits:\n  ipv6_prefix_bits: 129\n";
    CHECK_THROWS_WITH_AS(erikslund::core::Config::from_string(text),
                         "limits.ipv6_prefix_bits must be in [1, 128]",
                         erikslund::core::ConfigError);
}

TEST_CASE("configuration reads expanded traffic and source limits") {
    const std::string text = std::string(kMinimalConfig) + R"(limits:
  global_connections_per_second: 1234.0
  ipv6_prefix_bits: 56
  max_tracked_client_ips: 4096
  messages_per_second_per_connection: 12.5
  max_messages_per_ready_event: 77
)";
    const auto config = erikslund::core::Config::from_string(text);
    CHECK(config.limits.global_connections_per_second == 1234.0);
    CHECK(config.limits.ipv6_prefix_bits == 56);
    CHECK(config.limits.max_tracked_client_ips == 4096);
    CHECK(config.limits.messages_per_second_per_connection == 12.5);
    CHECK(config.limits.max_messages_per_ready_event == 77);
}

TEST_CASE("configuration rejects non-finite rate limits") {
    const auto rejected = [](std::string_view field, std::string_view value) {
        return erikslund::core::Config::from_string(
            std::string(kMinimalConfig) + "limits:\n  " + std::string(field) + ": " +
            std::string(value) + '\n');
    };

    for (const std::string_view field : {
             "connections_per_second_per_ip",
             "global_connections_per_second",
             "messages_per_second_per_connection",
             "bytes_per_second_per_connection",
             "messages_per_second_per_ip",
             "bytes_per_second_per_ip",
         }) {
        CHECK_THROWS_AS(rejected(field, ".nan"), erikslund::core::ConfigError);
        CHECK_THROWS_AS(rejected(field, ".inf"), erikslund::core::ConfigError);
    }
}

TEST_CASE("configuration reads bounded protocol extension allowlists") {
    const std::string text = std::string(kMinimalConfig) + R"(protocol:
  additional_allowed_methods:
    - mining.vendor_handshake
    - mining.vendor_extension
  additional_initial_methods:
    - mining.vendor_handshake
)";
    const auto config = erikslund::core::Config::from_string(text);
    CHECK(config.protocol.additional_allowed_methods ==
          std::vector<std::string>{"mining.vendor_handshake", "mining.vendor_extension"});
    CHECK(config.protocol.additional_initial_methods ==
          std::vector<std::string>{"mining.vendor_handshake"});

    auto replacement = config;
    replacement.protocol.additional_allowed_methods.push_back("mining.another_extension");
    CHECK(config.restart_required_changes(replacement).empty());
}

TEST_CASE("configuration rejects unsafe protocol extension allowlists") {
    const auto rejected = [](std::string_view protocol) {
        return erikslund::core::Config::from_string(std::string(kMinimalConfig) +
                                                    "protocol:\n" + std::string(protocol));
    };

    CHECK_THROWS_AS(rejected("  additional_allowed_methods: [eth_submitLogin]\n"),
                    erikslund::core::ConfigError);
    CHECK_THROWS_AS(rejected("  additional_allowed_methods: [mining.]\n"),
                    erikslund::core::ConfigError);
    CHECK_THROWS_AS(
        rejected("  additional_allowed_methods: [mining.vendor, mining.vendor]\n"),
        erikslund::core::ConfigError);
    const std::string non_ascii =
        "  additional_allowed_methods: [mining.v\xc3\xa9ndor]\n";
    CHECK_THROWS_AS(rejected(non_ascii), erikslund::core::ConfigError);
    CHECK_THROWS_AS(rejected("  additional_allowed_methods: [mining.vendor]\n"
                             "  additional_initial_methods: [mining.other]\n"),
                    erikslund::core::ConfigError);

    std::string too_many = "  additional_allowed_methods:\n";
    for (std::size_t index = 0; index <= erikslund::core::kMaximumAdditionalProtocolMethods;
         ++index)
        too_many += "    - mining.vendor_" + std::to_string(index) + '\n';
    CHECK_THROWS_AS(rejected(too_many), erikslund::core::ConfigError);

    const std::string oversized(erikslund::core::kMaximumProtocolMethodBytes, 'x');
    CHECK_THROWS_AS(rejected("  additional_allowed_methods: [mining." + oversized + "]\n"),
                    erikslund::core::ConfigError);
}

TEST_CASE("configuration accepts a separate backend HTTP health endpoint") {
    const std::string text = R"(
listeners:
  - name: sv1
    address: "127.0.0.1:3333"
pools:
  - name: primary
    backends:
      - name: pool-a
        address: "127.0.0.1:13333"
        health_address: "127.0.0.1:17777"
active_pool: primary
)";
    const auto config = erikslund::core::Config::from_string(text);
    CHECK(config.pools.front().backends.front().health_address == "127.0.0.1:17777");
}

TEST_CASE("configuration bounds the fixed reactor count") {
    const std::string text = std::string(kMinimalConfig) + "io_workers: 257\n";
    CHECK_THROWS_WITH_AS(erikslund::core::Config::from_string(text),
                         "io_workers must be in [0, 256]", erikslund::core::ConfigError);
}

TEST_CASE("configuration rejects unknown keys") {
    const std::string text = std::string(kMinimalConfig) + "scanner_bypass: true\n";
    CHECK_THROWS_AS(erikslund::core::Config::from_string(text), erikslund::core::ConfigError);
}

TEST_CASE("TLS listener requires both credential paths") {
    const std::string text = R"(
listeners:
  - name: sv1-tls
    address: "127.0.0.1:3334"
    tls: true
pools:
  - name: primary
    backends:
      - name: pool-a
        address: "127.0.0.1:13333"
active_pool: primary
)";
    CHECK_THROWS_WITH_AS(erikslund::core::Config::from_string(text),
                         "TLS listener sv1-tls requires certificate_file and private_key_file",
                         erikslund::core::ConfigError);
}

TEST_CASE("configuration rejects an active pool that does not exist") {
    std::string text(kMinimalConfig);
    const std::size_t position = text.rfind("primary");
    REQUIRE(position != std::string::npos);
    text.replace(position, std::string("primary").size(), "missing");
    CHECK_THROWS_AS(erikslund::core::Config::from_string(text), erikslund::core::ConfigError);
}

TEST_CASE("certificate path changes reload without changing listener topology") {
    auto current = erikslund::core::Config::from_string(std::string(kMinimalConfig));
    current.listeners.front().tls = true;
    current.listeners.front().certificate_file = "/tls/old-cert.pem";
    current.listeners.front().private_key_file = "/tls/old-key.pem";

    auto replacement = current;
    replacement.listeners.front().certificate_file = "/tls/new-cert.pem";
    replacement.listeners.front().private_key_file = "/tls/new-key.pem";
    CHECK(current.restart_required_changes(replacement).empty());

    replacement.listeners.front().address = "127.0.0.1:4333";
    CHECK(current.restart_required_changes(replacement) ==
          std::vector<std::string>{"listeners"});
}
