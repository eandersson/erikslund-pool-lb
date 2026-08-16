#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <poll.h>
#include <sys/socket.h>

#include "core/config.hpp"
#include "core/service_state.hpp"
#include "net/endpoint.hpp"
#include "routing/health_monitor.hpp"
#include "routing/router.hpp"
#include "socket_test_utils.hpp"

using namespace std::chrono_literals;

namespace {

class FakeHealthServer {
public:
    explicit FakeHealthServer(bool healthy)
        : FakeHealthServer(std::string(
              healthy
                  ? "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n"
                  : "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 9\r\n"
                    "Connection: close\r\n\r\ndegraded\n")) {}

    explicit FakeHealthServer(std::string response)
        : listener_(erikslund::test::bind_loopback_listener(true)),
          response_(std::move(response)),
          thread_([this](const std::stop_token& token) { run(token); }) {}

    [[nodiscard]] std::uint16_t port() const noexcept {
        return listener_.port;
    }

    [[nodiscard]] int accepted() const noexcept {
        return accepted_.load(std::memory_order_relaxed);
    }

private:
    void run(const std::stop_token& token) {
        while (!token.stop_requested()) {
            pollfd descriptor{listener_.socket.get(), POLLIN, 0};
            if (::poll(&descriptor, 1, 100) <= 0)
                continue;
            erikslund::net::UniqueFd client(
                ::accept4(listener_.socket.get(), nullptr, nullptr, SOCK_CLOEXEC));
            if (!client)
                continue;
            accepted_.fetch_add(1, std::memory_order_relaxed);
            while (true) {
                const std::string line = erikslund::test::read_line(client.get());
                if (line.empty() || line == "\r\n")
                    break;
            }
            erikslund::test::send_all(client.get(), response_);
        }
    }

    erikslund::test::BoundListener listener_;
    std::string response_;
    std::atomic<int> accepted_{0};
    std::jthread thread_;
};

class SilentHealthServer {
public:
    SilentHealthServer()
        : listener_(erikslund::test::bind_loopback_listener(true)),
          thread_([this](const std::stop_token& token) { run(token); }) {}

    [[nodiscard]] std::uint16_t port() const noexcept {
        return listener_.port;
    }

    [[nodiscard]] int accepted() const noexcept {
        return accepted_.load(std::memory_order_relaxed);
    }

private:
    void run(const std::stop_token& token) {
        while (!token.stop_requested()) {
            pollfd descriptor{listener_.socket.get(), POLLIN, 0};
            if (::poll(&descriptor, 1, 100) <= 0)
                continue;
            erikslund::net::UniqueFd client(
                ::accept4(listener_.socket.get(), nullptr, nullptr, SOCK_CLOEXEC));
            if (!client)
                continue;
            accepted_.fetch_add(1, std::memory_order_relaxed);
            while (!token.stop_requested())
                std::this_thread::sleep_for(10ms);
        }
    }

    erikslund::test::BoundListener listener_;
    std::atomic<int> accepted_{0};
    std::jthread thread_;
};

erikslund::core::Config health_config(std::uint16_t mining_port,
                                      std::uint16_t health_port) {
    erikslund::core::Config config;
    config.listeners = {{.name = "unused",
                         .address = "127.0.0.1:3333",
                         .tls = false,
                         .certificate_file = {},
                         .private_key_file = {}}};
    config.pools = {{.name = "primary",
                     .backends = {{.name = "backend",
                                   .address = "127.0.0.1:" + std::to_string(mining_port),
                                   .health_address =
                                       "127.0.0.1:" + std::to_string(health_port),
                                   .send_proxy_v2 = false}}}};
    config.active_pool = "primary";
    config.health.interval_seconds = 60;
    config.health.connect_timeout_milliseconds = 500;
    config.health.rise_checks = 1;
    config.health.fall_checks = 1;
    return config;
}

} // namespace

TEST_CASE("HTTP backend health avoids opening the mining listener") {
    auto mining = erikslund::test::bind_loopback_listener(true);
    FakeHealthServer health(true);
    REQUIRE(mining.port != 0);
    REQUIRE(health.port() != 0);

    const auto config = std::make_shared<const erikslund::core::Config>(
        health_config(mining.port, health.port()));
    erikslund::core::ServiceState state;
    const auto routing = erikslund::routing::make_routing_table(*config);
    state.publish(config, routing);
    const auto backend = routing->pools.front().backends.front();

    erikslund::routing::HealthMonitor monitor(state);
    std::jthread thread([&monitor](const std::stop_token& token) { monitor.run(token); });
    REQUIRE(erikslund::test::wait_until([&backend] { return backend->healthy.load(); }, 2s));
    thread.request_stop();

    CHECK(health.accepted() >= 1);
    erikslund::net::UniqueFd unexpected_miner(
        ::accept4(mining.socket.get(), nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK));
    CHECK_FALSE(unexpected_miner);
}

TEST_CASE("HTTP backend health requires a successful readiness response") {
    auto mining = erikslund::test::bind_loopback_listener(true);
    FakeHealthServer health(false);
    REQUIRE(mining.port != 0);
    REQUIRE(health.port() != 0);

    const auto config = std::make_shared<const erikslund::core::Config>(
        health_config(mining.port, health.port()));
    erikslund::core::ServiceState state;
    const auto routing = erikslund::routing::make_routing_table(*config);
    state.publish(config, routing);
    const auto backend = routing->pools.front().backends.front();
    backend->healthy.store(true);

    erikslund::routing::HealthMonitor monitor(state);
    std::jthread thread([&monitor](const std::stop_token& token) { monitor.run(token); });
    REQUIRE(erikslund::test::wait_until([&backend] { return !backend->healthy.load(); }, 2s));
    thread.request_stop();

    CHECK(health.accepted() >= 1);
}

TEST_CASE("HTTP health rejects a status line larger than its fixed buffer") {
    constexpr std::size_t kOversizedStatusPaddingBytes = 600;
    auto mining = erikslund::test::bind_loopback_listener(true);
    std::string response = "HTTP/1.1 200 ";
    response.append(kOversizedStatusPaddingBytes, 'x');
    response += "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    FakeHealthServer health(std::move(response));
    REQUIRE(mining.port != 0);
    REQUIRE(health.port() != 0);

    const auto config = std::make_shared<const erikslund::core::Config>(
        health_config(mining.port, health.port()));
    erikslund::core::ServiceState state;
    const auto routing = erikslund::routing::make_routing_table(*config);
    state.publish(config, routing);
    const auto backend = routing->pools.front().backends.front();
    backend->healthy.store(true);

    erikslund::routing::HealthMonitor monitor(state);
    std::jthread thread([&monitor](const std::stop_token& token) { monitor.run(token); });
    REQUIRE(erikslund::test::wait_until([&backend] { return !backend->healthy.load(); }, 2s));
    thread.request_stop();

    CHECK(health.accepted() >= 1);
}

TEST_CASE("health addresses share one backend deadline") {
    constexpr auto kOverallTimeout = 1'200ms;
    constexpr auto kMaximumExpectedElapsed = 1'000ms;
    SilentHealthServer silent;
    FakeHealthServer health(true);
    auto mining = erikslund::test::bind_loopback_listener(true);
    REQUIRE(silent.port() != 0);
    REQUIRE(health.port() != 0);
    REQUIRE(mining.port != 0);

    auto mutable_config = health_config(mining.port, health.port());
    mutable_config.health.connect_timeout_milliseconds =
        static_cast<int>(kOverallTimeout.count());
    const auto config =
        std::make_shared<const erikslund::core::Config>(std::move(mutable_config));
    erikslund::core::ServiceState state;
    const auto routing = erikslund::routing::make_routing_table(*config);
    state.publish(config, routing);
    const auto backend = routing->pools.front().backends.front();
    const auto silent_addresses = erikslund::net::resolve_endpoints(
        erikslund::net::parse_endpoint("127.0.0.1:" + std::to_string(silent.port())));
    backend->health_socket_addresses.insert(backend->health_socket_addresses.begin(),
                                            silent_addresses.front());

    erikslund::routing::HealthMonitor monitor(state);
    const auto started_at = std::chrono::steady_clock::now();
    std::jthread thread([&monitor](const std::stop_token& token) { monitor.run(token); });
    REQUIRE(erikslund::test::wait_until([&backend] { return backend->healthy.load(); }, 2s));
    const auto elapsed = std::chrono::steady_clock::now() - started_at;
    thread.request_stop();
    thread.join();

    CHECK(silent.accepted() == 1);
    CHECK(health.accepted() == 1);
    CHECK(elapsed < kMaximumExpectedElapsed);
}
