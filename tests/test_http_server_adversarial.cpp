// Adversarial integration coverage for the embedded observability HTTP server.
#include <doctest/doctest.h>

#include <cstdint>
#include <memory>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>

#include "api/http_server.hpp"
#include "core/config.hpp"
#include "core/service_state.hpp"
#include "routing/router.hpp"
#include "socket_test_utils.hpp"

namespace {

std::string request(std::uint16_t port, std::string_view bytes) {
    auto client = erikslund::test::connect_loopback(port);
    if (!client || !erikslund::test::send_all(client.get(), bytes))
        return {};
    return erikslund::test::read_to_close(client.get());
}

erikslund::core::Config adversarial_http_config(std::uint16_t port) {
    erikslund::core::Config config;
    config.listeners = {{.name = "unused",
                         .address = "127.0.0.1:3333",
                         .tls = false,
                         .certificate_file = {},
                         .private_key_file = {}}};
    config.pools = {{.name = "<script>&pool",
                     .backends = {{.name = "backend\"\n\\",
                                   .address = "127.0.0.1:13333",
                                   .health_address = {},
                                   .send_proxy_v2 = false}}}};
    config.active_pool = "<script>&pool";
    config.api_address = "127.0.0.1:" + std::to_string(port);
    return config;
}

} // namespace

TEST_CASE("HTTP status and metrics escape configuration-controlled labels") {
    const std::uint16_t port = erikslund::test::unused_loopback_port();
    REQUIRE(port != 0);
    const erikslund::core::Config config = adversarial_http_config(port);
    erikslund::core::ServiceState state;
    auto routing = erikslund::routing::make_routing_table(config);
    routing->pools.front().backends.front()->healthy.store(true);
    state.publish(std::make_shared<const erikslund::core::Config>(config), routing);
    state.tls_certificates.store(
        std::make_shared<const erikslund::core::TlsCertificateStatuses>(
            erikslund::core::TlsCertificateStatuses{{
                .listener_name = "tls\"\n\\",
                .expiry_timestamp_seconds = 4'102'444'800,
            }}));

    erikslund::api::HttpServer server(config, state);
    std::jthread thread([&server](const std::stop_token& token) { server.run(token); });

    const std::string status = request(
        port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    CHECK(status.find("<script>") == std::string::npos);
    CHECK(status.find("&lt;script&gt;&amp;pool/backend&quot;") != std::string::npos);
    CHECK(status.find("TLS tls&quot;") != std::string::npos);

    const std::string metrics = request(
        port, "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    CHECK(metrics.find(
              R"(pool_lb_backend_up{pool="<script>&pool",backend="backend\"\n\\"} 1)") !=
          std::string::npos);
    CHECK(metrics.find(
              R"(pool_lb_tls_certificate_expiry_timestamp_seconds{listener="tls\"\n\\"} 4102444800)") !=
          std::string::npos);
    thread.request_stop();
}

TEST_CASE("oversized HTTP headers are rejected without poisoning the sole worker") {
    const std::uint16_t port = erikslund::test::unused_loopback_port();
    REQUIRE(port != 0);
    const erikslund::core::Config config = adversarial_http_config(port);
    erikslund::core::ServiceState state;
    auto routing = erikslund::routing::make_routing_table(config);
    routing->pools.front().backends.front()->healthy.store(true);
    state.publish(std::make_shared<const erikslund::core::Config>(config), routing);

    erikslund::api::HttpServer server(config, state);
    std::jthread thread([&server](const std::stop_token& token) { server.run(token); });

    const std::string oversized = "GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Fill: " +
                                  std::string(5'000, 'a') +
                                  "\r\nConnection: close\r\n\r\n";
    const std::string rejected = request(port, oversized);
    CHECK_FALSE(rejected.starts_with("HTTP/1.1 200 "));

    const std::string healthy = request(
        port, "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    CHECK(healthy.starts_with("HTTP/1.1 200 OK\r\n"));
    thread.request_stop();
}
