#include <doctest/doctest.h>

#include <chrono>
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

std::string http_request(std::uint16_t port, std::string_view request) {
    auto client = erikslund::test::connect_loopback(port);
    if (!client || !erikslund::test::send_all(client.get(), request))
        return {};
    return erikslund::test::read_to_close(client.get());
}

} // namespace

TEST_CASE("HTTP server reports readiness and backend attempt/error counters") {
    const std::uint16_t port = erikslund::test::unused_loopback_port();
    REQUIRE(port != 0);
    erikslund::core::Config config;
    config.listeners = {{.name = "unused",
                         .address = "127.0.0.1:3333",
                         .tls = false,
                         .certificate_file = {},
                         .private_key_file = {}}};
    config.pools = {{.name = "primary",
                     .backends = {{.name = "backend",
                                   .address = "127.0.0.1:13333",
                                   .health_address = {},
                                   .send_proxy_v2 = false}}}};
    config.active_pool = "primary";
    config.api_address = "127.0.0.1:" + std::to_string(port);

    erikslund::core::ServiceState state;
    auto routing = erikslund::routing::make_routing_table(config);
    auto backend = routing->pools.front().backends.front();
    backend->healthy.store(true);
    backend->connection_attempts.store(25);
    backend->connection_errors.store(2);
    state.publish(std::make_shared<const erikslund::core::Config>(config), routing);
    state.stats.io_workers.store(3);
    state.stats.tls_reload_successes.store(4);
    state.stats.tls_reload_failures.store(1);
    const std::int64_t certificate_expiry =
        std::chrono::duration_cast<std::chrono::seconds>(
            (std::chrono::system_clock::now() + std::chrono::days(5)).time_since_epoch())
            .count();
    state.tls_certificates.store(
        std::make_shared<const erikslund::core::TlsCertificateStatuses>(
            erikslund::core::TlsCertificateStatuses{{
                .listener_name = "sv1-tls",
                .expiry_timestamp_seconds = certificate_expiry,
            }}));

    erikslund::api::HttpServer server(config, state);
    std::jthread thread([&server](const std::stop_token& token) { server.run(token); });

    const std::string health = http_request(
        port, "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    CHECK(health.starts_with("HTTP/1.1 200 OK\r\n"));
    CHECK(health.find("X-Content-Type-Options: nosniff\r\n") != std::string::npos);
    CHECK(health.ends_with("ok\n"));

    const std::string head = http_request(
        port, "HEAD /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    CHECK(head.starts_with("HTTP/1.1 200 OK\r\n"));
    CHECK(head.find("Content-Length: 3\r\n") != std::string::npos);
    CHECK(head.ends_with("\r\n\r\n"));

    const std::string metrics = http_request(
        port, "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    CHECK(metrics.find("pool_lb_io_workers 3\n") != std::string::npos);
    CHECK(metrics.find("# HELP pool_lb_queued_bytes_limit Current process-wide queued-byte "
                       "limit.\n# TYPE pool_lb_queued_bytes_limit gauge\n"
                       "pool_lb_queued_bytes_limit " +
                       std::to_string(config.limits.max_queued_bytes) + "\n") !=
          std::string::npos);
    CHECK(metrics.find("pool_lb_tls_certificate_reloads_total{result=\"success\"} 4\n") !=
          std::string::npos);
    CHECK(metrics.find("pool_lb_tls_certificate_reloads_total{result=\"failure\"} 1\n") !=
          std::string::npos);
    CHECK(metrics.find(
              "pool_lb_tls_certificate_expiry_timestamp_seconds{listener=\"sv1-tls\"} " +
              std::to_string(certificate_expiry) + "\n") != std::string::npos);
    CHECK(metrics.find("pool_lb_backend_connection_attempts_total{pool=\"primary\","
                       "backend=\"backend\"} 25\n") != std::string::npos);
    CHECK(metrics.find("pool_lb_backend_connection_errors_total{pool=\"primary\","
                       "backend=\"backend\"} 2\n") != std::string::npos);

    const std::string status = http_request(
        port, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    CHECK(status.find("TLS CERTIFICATE EXPIRING") != std::string::npos);
    CHECK(status.find("TLS sv1-tls certificate</td><td class=\"warn\">expires ") !=
          std::string::npos);
    CHECK(status.find("queued bytes</td><td>0 / " +
                      std::to_string(config.limits.max_queued_bytes) +
                      " (high water 0)</td>") != std::string::npos);

    const std::int64_t expired_certificate =
        std::chrono::duration_cast<std::chrono::seconds>(
            (std::chrono::system_clock::now() - std::chrono::days(1)).time_since_epoch())
            .count();
    state.tls_certificates.store(
        std::make_shared<const erikslund::core::TlsCertificateStatuses>(
            erikslund::core::TlsCertificateStatuses{{
                .listener_name = "sv1-tls",
                .expiry_timestamp_seconds = expired_certificate,
            }}));
    const std::string expired_status = http_request(
        port, "GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    CHECK(expired_status.find("TLS CERTIFICATE EXPIRED") != std::string::npos);
    CHECK(expired_status.find("TLS sv1-tls certificate</td><td class=\"bad\">expired ") !=
          std::string::npos);

    const std::string method = http_request(
        port, "POST /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    CHECK(method.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));

    backend->healthy.store(false);
    const std::string degraded = http_request(
        port, "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    CHECK(degraded.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    CHECK(degraded.ends_with("degraded\n"));
    thread.request_stop();
}

TEST_CASE("slow HTTP client does not block health checks") {
    const std::uint16_t port = erikslund::test::unused_loopback_port();
    REQUIRE(port != 0);
    erikslund::core::Config config;
    config.listeners = {{.name = "unused",
                         .address = "127.0.0.1:3333",
                         .tls = false,
                         .certificate_file = {},
                         .private_key_file = {}}};
    config.pools = {{.name = "primary",
                     .backends = {{.name = "backend",
                                   .address = "127.0.0.1:13333",
                                   .health_address = {}}}}};
    config.active_pool = "primary";
    config.api_address = "127.0.0.1:" + std::to_string(port);

    erikslund::core::ServiceState state;
    auto routing = erikslund::routing::make_routing_table(config);
    routing->pools.front().backends.front()->healthy.store(true);
    state.publish(std::make_shared<const erikslund::core::Config>(config), routing);

    erikslund::api::HttpServer server(config, state);
    std::jthread thread([&server](const std::stop_token& token) { server.run(token); });

    auto slow_client = erikslund::test::connect_loopback(port);
    REQUIRE(slow_client);
    REQUIRE(erikslund::test::send_all(slow_client.get(), "GET /healthz"));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    const auto started = std::chrono::steady_clock::now();
    const std::string health = http_request(
        port, "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    const auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(health.starts_with("HTTP/1.1 200 OK\r\n"));
    CHECK(elapsed < std::chrono::seconds(1));
    thread.request_stop();
}
