#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <poll.h>
#include <sys/socket.h>

#include "core/config.hpp"
#include "core/service_state.hpp"
#include "net/endpoint.hpp"
#include "net/server.hpp"
#include "routing/router.hpp"
#include "socket_test_utils.hpp"

using namespace std::chrono_literals;

namespace {

class FakeBackend {
public:
    explicit FakeBackend(std::size_t expected_lines = 1)
        : listener_(erikslund::test::bind_loopback_listener(true)),
          expected_lines_(expected_lines) {
        thread_ = std::jthread([this](const std::stop_token& token) { run(token); });
    }

    [[nodiscard]] std::uint16_t port() const noexcept {
        return listener_.port;
    }

    [[nodiscard]] int accepted() const noexcept {
        return accepted_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] std::string request() const {
        std::lock_guard lock(mutex_);
        return request_;
    }

private:
    void run(const std::stop_token& token) {
        while (!token.stop_requested()) {
            pollfd descriptor{listener_.socket.get(), POLLIN, 0};
            const int ready = ::poll(&descriptor, 1, 100);
            if (ready <= 0)
                continue;
            erikslund::net::UniqueFd client(
                ::accept4(listener_.socket.get(), nullptr, nullptr, SOCK_CLOEXEC));
            if (!client)
                continue;
            accepted_.fetch_add(1, std::memory_order_relaxed);
            std::string request;
            for (std::size_t line_index = 0; line_index < expected_lines_; ++line_index) {
                const std::string line = erikslund::test::read_line(client.get());
                if (line.empty())
                    break;
                request += line;
            }
            {
                std::lock_guard lock(mutex_);
                request_ = std::move(request);
            }
            erikslund::test::send_all(
                client.get(), "{\"id\":1,\"result\":true,\"error\":null}\n");
        }
    }

    erikslund::test::BoundListener listener_;
    std::size_t expected_lines_;
    std::jthread thread_;
    std::atomic<int> accepted_{0};
    mutable std::mutex mutex_;
    std::string request_;
};

class HalfCloseBackend {
public:
    HalfCloseBackend(std::size_t expected_request_bytes, std::string response)
        : listener_(erikslund::test::bind_loopback_listener(true)),
          expected_request_bytes_(expected_request_bytes), response_(std::move(response)),
          thread_([this](const std::stop_token& token) { run(token); }) {}

    [[nodiscard]] std::uint16_t port() const noexcept {
        return listener_.port;
    }

    [[nodiscard]] bool completed() const noexcept {
        return completed_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] std::string request() const {
        std::lock_guard lock(mutex_);
        return request_;
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

            std::string request;
            request.reserve(expected_request_bytes_);
            std::string input(16'384, '\0');
            while (request.size() < expected_request_bytes_) {
                const std::size_t remaining = expected_request_bytes_ - request.size();
                const ssize_t received =
                    ::recv(client.get(), input.data(), std::min(input.size(), remaining), 0);
                if (received <= 0)
                    break;
                request.append(input.data(), static_cast<std::size_t>(received));
            }
            const bool complete_request = request.size() == expected_request_bytes_;
            {
                std::lock_guard lock(mutex_);
                request_ = std::move(request);
            }
            if (complete_request)
                erikslund::test::send_all(client.get(), response_);
            completed_.store(true, std::memory_order_relaxed);
            return;
        }
    }

    erikslund::test::BoundListener listener_;
    std::size_t expected_request_bytes_;
    std::string response_;
    std::atomic<bool> completed_{false};
    mutable std::mutex mutex_;
    std::string request_;
    std::jthread thread_;
};

class SourceRecordingBackend {
public:
    SourceRecordingBackend()
        : listener_(erikslund::test::bind_loopback_listener(true)),
          thread_([this](const std::stop_token& token) { run(token); }) {}

    [[nodiscard]] std::uint16_t port() const noexcept {
        return listener_.port;
    }

    [[nodiscard]] int accepted() const noexcept {
        return accepted_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] std::vector<std::string> source_hosts() const {
        std::lock_guard lock(mutex_);
        return source_hosts_;
    }

private:
    void run(const std::stop_token& token) {
        while (!token.stop_requested()) {
            pollfd descriptor{listener_.socket.get(), POLLIN, 0};
            if (::poll(&descriptor, 1, 100) <= 0)
                continue;
            sockaddr_storage peer{};
            socklen_t peer_length = sizeof(peer);
            erikslund::net::UniqueFd client(
                ::accept4(listener_.socket.get(), reinterpret_cast<sockaddr*>(&peer),
                          &peer_length, SOCK_CLOEXEC));
            if (!client)
                continue;
            {
                std::lock_guard lock(mutex_);
                source_hosts_.push_back(erikslund::net::address_host(peer));
            }
            accepted_.fetch_add(1, std::memory_order_relaxed);
            if (!erikslund::test::read_line(client.get()).empty())
                erikslund::test::send_all(
                    client.get(), "{\"id\":1,\"result\":true,\"error\":null}\n");
        }
    }

    erikslund::test::BoundListener listener_;
    std::atomic<int> accepted_{0};
    mutable std::mutex mutex_;
    std::vector<std::string> source_hosts_;
    std::jthread thread_;
};

std::string patterned_payload(std::size_t size) {
    std::string output;
    output.reserve(size);
    for (std::size_t index = 0; index < size; ++index)
        output.push_back(static_cast<char>('a' + index % 23));
    return output;
}

erikslund::core::Config reactor_config(std::uint16_t listener_port,
                                       std::uint16_t backend_port) {
    erikslund::core::Config config;
    config.listeners = {{.name = "unit-sv1",
                         .address = "127.0.0.1:" + std::to_string(listener_port),
                         .tls = false,
                         .certificate_file = {},
                         .private_key_file = {}}};
    config.pools = {{.name = "primary",
                     .backends = {{.name = "backend",
                                   .address = "127.0.0.1:" +
                                              std::to_string(backend_port),
                                   .health_address = {},
                                   .send_proxy_v2 = false}}}};
    config.active_pool = "primary";
    config.io_workers = 1;
    config.limits.max_connections = 32;
    config.limits.max_connections_per_ip = 32;
    config.limits.connections_per_second_per_ip = 100.0;
    config.limits.connection_burst_per_ip = 32;
    config.limits.messages_per_second_per_connection = 0.001;
    config.limits.message_burst_per_connection = 1;
    config.limits.first_message_timeout_seconds = 1;
    config.limits.upstream_connect_timeout_milliseconds = 2'000;
    return config;
}

} // namespace

TEST_CASE("reactor rejects before connect, expires setup, falls back, and relays") {
    FakeBackend backend;
    REQUIRE(backend.port() != 0);
    const std::uint16_t listener_port = erikslund::test::unused_loopback_port();
    const std::uint16_t closed_backend_port = erikslund::test::unused_loopback_port();
    REQUIRE(listener_port != 0);
    REQUIRE(closed_backend_port != 0);

    const auto config = std::make_shared<const erikslund::core::Config>(
        reactor_config(listener_port, backend.port()));
    erikslund::core::ServiceState state;
    auto routing = erikslund::routing::make_routing_table(*config);
    auto backend_state = routing->pools.front().backends.front();
    backend_state->healthy.store(true);
    const auto closed_address = erikslund::net::resolve_endpoints(
        erikslund::net::parse_endpoint("127.0.0.1:" +
                                       std::to_string(closed_backend_port)));
    backend_state->socket_addresses.insert(backend_state->socket_addresses.begin(),
                                            closed_address.front());
    state.publish(config, routing);

    erikslund::net::EdgeServer edge(*config, state);
    edge.start();

    SUBCASE("invalid first bytes never open an upstream socket") {
        auto client = erikslund::test::connect_loopback(listener_port);
        REQUIRE(client);
        REQUIRE(erikslund::test::send_all(client.get(), "GET / HTTP/1.1\n"));
        CHECK(erikslund::test::read_line(client.get()).empty());
        CHECK(backend.accepted() == 0);
        CHECK(state.stats.snapshot().rejected_protocol == 1);
    }

    SUBCASE("first-message deadline closes an idle admitted client") {
        auto client = erikslund::test::connect_loopback(listener_port);
        REQUIRE(client);
        CHECK(erikslund::test::wait_until(
            [&client] {
                char byte = '\0';
                return ::recv(client.get(), &byte, 1, MSG_DONTWAIT) == 0;
            },
            3s));
        CHECK(backend.accepted() == 0);
    }

    SUBCASE("per-connection traffic budget closes a message flood before upstream connect") {
        auto client = erikslund::test::connect_loopback(listener_port);
        REQUIRE(client);
        constexpr std::string_view request =
            "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n"
            "{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[]}\n";
        REQUIRE(erikslund::test::send_all(client.get(), request));
        CHECK(erikslund::test::read_line(client.get()).empty());
        CHECK(backend.accepted() == 0);
        CHECK(state.stats.snapshot().rejected_traffic_rate == 1);
    }

    SUBCASE("failed first address falls through to a healthy address") {
        auto client = erikslund::test::connect_loopback(listener_port);
        REQUIRE(client);
        constexpr std::string_view request =
            "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"unit\"]}\n";
        REQUIRE(erikslund::test::send_all(client.get(), request));
        CHECK(erikslund::test::read_line(client.get()) ==
              "{\"id\":1,\"result\":true,\"error\":null}\n");
        REQUIRE(erikslund::test::wait_until([&backend] { return backend.accepted() == 1; }, 1s));
        CHECK(backend.request() == request);
        CHECK(backend_state->connection_attempts.load() == 2);
        CHECK(backend_state->connection_errors.load() == 1);
    }

    edge.stop();
}

TEST_CASE("reactor relays many complete messages received in one client write") {
    constexpr std::size_t kMessageCount = 128;
    FakeBackend backend(kMessageCount);
    REQUIRE(backend.port() != 0);
    const std::uint16_t listener_port = erikslund::test::unused_loopback_port();
    REQUIRE(listener_port != 0);

    auto mutable_config = reactor_config(listener_port, backend.port());
    mutable_config.limits.messages_per_second_per_connection = 1'000.0;
    mutable_config.limits.message_burst_per_connection = kMessageCount;
    const auto config =
        std::make_shared<const erikslund::core::Config>(std::move(mutable_config));
    erikslund::core::ServiceState state;
    auto routing = erikslund::routing::make_routing_table(*config);
    routing->pools.front().backends.front()->healthy.store(true);
    state.publish(config, routing);

    erikslund::net::EdgeServer edge(*config, state);
    edge.start();

    std::string requests;
    for (std::size_t message_index = 0; message_index < kMessageCount; ++message_index) {
        requests += "{\"id\":" + std::to_string(message_index + 1) +
                    ",\"method\":\"mining.subscribe\",\"params\":[]}\n";
    }
    auto client = erikslund::test::connect_loopback(listener_port);
    REQUIRE(client);
    REQUIRE(erikslund::test::send_all(client.get(), requests));
    CHECK(erikslund::test::read_line(client.get()) ==
          "{\"id\":1,\"result\":true,\"error\":null}\n");
    REQUIRE(erikslund::test::wait_until([&backend, &requests] { return backend.request() == requests; },
                                        1s));
    CHECK(state.stats.snapshot().rejected_protocol == 0);
    CHECK(state.stats.snapshot().rejected_traffic_rate == 0);

    edge.stop();
}

TEST_CASE("reactor drains half-closed peers across multiple fairness budgets") {
    constexpr std::size_t kReadyEventBudgetBytes = 65'536;
    constexpr std::size_t kDirectionalPayloadBytes = kReadyEventBudgetBytes * 3;
    constexpr std::size_t kParameterBytes = 400;
    const std::string parameter(kParameterBytes, 'x');
    std::string request;
    for (std::size_t request_id = 1; request.size() < kDirectionalPayloadBytes; ++request_id)
        request += "{\"id\":" + std::to_string(request_id) +
                   ",\"method\":\"mining.subscribe\",\"params\":[\"" + parameter +
                   "\"]}\n";
    const std::string response = patterned_payload(kDirectionalPayloadBytes);

    HalfCloseBackend backend(request.size(), response);
    REQUIRE(backend.port() != 0);
    const std::uint16_t listener_port = erikslund::test::unused_loopback_port();
    REQUIRE(listener_port != 0);

    auto mutable_config = reactor_config(listener_port, backend.port());
    mutable_config.limits.messages_per_second_per_connection = 1'000'000.0;
    mutable_config.limits.message_burst_per_connection = 10'000;
    mutable_config.limits.bytes_per_second_per_connection = 1'000'000'000.0;
    mutable_config.limits.byte_burst_per_connection = 1'000'000;
    mutable_config.limits.messages_per_second_per_ip = 1'000'000.0;
    mutable_config.limits.message_burst_per_ip = 10'000;
    mutable_config.limits.bytes_per_second_per_ip = 1'000'000'000.0;
    mutable_config.limits.byte_burst_per_ip = 1'000'000;
    mutable_config.limits.idle_timeout_seconds = 5;
    const auto config =
        std::make_shared<const erikslund::core::Config>(std::move(mutable_config));
    erikslund::core::ServiceState state;
    auto routing = erikslund::routing::make_routing_table(*config);
    routing->pools.front().backends.front()->healthy.store(true);
    state.publish(config, routing);

    erikslund::net::EdgeServer edge(*config, state);
    edge.start();
    auto client = erikslund::test::connect_loopback(listener_port);
    REQUIRE(client);
    REQUIRE(erikslund::test::send_all(client.get(), request));
    REQUIRE(::shutdown(client.get(), SHUT_WR) == 0);

    const std::string relayed_response = erikslund::test::read_to_close(client.get());
    CHECK(relayed_response == response);
    REQUIRE(erikslund::test::wait_until([&backend] { return backend.completed(); }, 2s));
    CHECK(backend.request() == request);
    REQUIRE(erikslund::test::wait_until(
        [&state] { return state.stats.queued_bytes.load() == 0; }, 1s));

    edge.stop();
}

TEST_CASE("reactor rotates configured upstream source addresses") {
    SourceRecordingBackend backend;
    REQUIRE(backend.port() != 0);
    const std::uint16_t listener_port = erikslund::test::unused_loopback_port();
    REQUIRE(listener_port != 0);

    auto mutable_config = reactor_config(listener_port, backend.port());
    mutable_config.upstream_source_addresses = {"127.0.0.2", "127.0.0.3"};
    const auto config =
        std::make_shared<const erikslund::core::Config>(std::move(mutable_config));
    erikslund::core::ServiceState state;
    auto routing = erikslund::routing::make_routing_table(*config);
    routing->pools.front().backends.front()->healthy.store(true);
    state.publish(config, routing);

    erikslund::net::EdgeServer edge(*config, state);
    edge.start();
    constexpr std::string_view request =
        "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n";
    constexpr std::string_view response = "{\"id\":1,\"result\":true,\"error\":null}\n";
    for (int connection = 0; connection < 2; ++connection) {
        auto client = erikslund::test::connect_loopback(listener_port);
        REQUIRE(client);
        REQUIRE(erikslund::test::send_all(client.get(), request));
        CHECK(erikslund::test::read_line(client.get()) == response);
    }
    REQUIRE(erikslund::test::wait_until([&backend] { return backend.accepted() == 2; }, 1s));
    CHECK(backend.source_hosts() ==
          std::vector<std::string>{"127.0.0.2", "127.0.0.3"});

    edge.stop();
}

TEST_CASE("reactor retries alternate source addresses after a bind failure") {
    SourceRecordingBackend backend;
    REQUIRE(backend.port() != 0);
    const std::uint16_t listener_port = erikslund::test::unused_loopback_port();
    REQUIRE(listener_port != 0);

    auto mutable_config = reactor_config(listener_port, backend.port());
    mutable_config.upstream_source_addresses = {"192.0.2.254", "127.0.0.2"};
    const auto config =
        std::make_shared<const erikslund::core::Config>(std::move(mutable_config));
    erikslund::core::ServiceState state;
    auto routing = erikslund::routing::make_routing_table(*config);
    auto backend_state = routing->pools.front().backends.front();
    backend_state->healthy.store(true);
    state.publish(config, routing);

    erikslund::net::EdgeServer edge(*config, state);
    edge.start();
    auto client = erikslund::test::connect_loopback(listener_port);
    REQUIRE(client);
    constexpr std::string_view request =
        "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n";
    REQUIRE(erikslund::test::send_all(client.get(), request));
    CHECK(erikslund::test::read_line(client.get()) ==
          "{\"id\":1,\"result\":true,\"error\":null}\n");
    REQUIRE(erikslund::test::wait_until([&backend] { return backend.accepted() == 1; }, 1s));
    CHECK(backend.source_hosts() == std::vector<std::string>{"127.0.0.2"});
    CHECK(backend_state->connection_attempts.load() == 2);
    CHECK(backend_state->connection_errors.load() == 1);

    edge.stop();
}

TEST_CASE("reactor routes connections through their accept-time runtime snapshot") {
    FakeBackend original_backend;
    FakeBackend replacement_backend;
    REQUIRE(original_backend.port() != 0);
    REQUIRE(replacement_backend.port() != 0);
    const std::uint16_t listener_port = erikslund::test::unused_loopback_port();
    REQUIRE(listener_port != 0);

    auto original_mutable_config = reactor_config(listener_port, original_backend.port());
    original_mutable_config.limits.first_message_timeout_seconds = 5;
    const auto original_config =
        std::make_shared<const erikslund::core::Config>(std::move(original_mutable_config));
    erikslund::core::ServiceState state;
    auto original_routing = erikslund::routing::make_routing_table(*original_config);
    original_routing->pools.front().backends.front()->healthy.store(true);
    state.publish(original_config, original_routing);

    erikslund::net::EdgeServer edge(*original_config, state);
    edge.start();

    auto original_client = erikslund::test::connect_loopback(listener_port);
    REQUIRE(original_client);
    REQUIRE(erikslund::test::wait_until(
        [&state] { return state.stats.snapshot().accepted_connections == 1; }, 1s));

    auto replacement_mutable_config =
        reactor_config(listener_port, replacement_backend.port());
    replacement_mutable_config.limits.first_message_timeout_seconds = 5;
    const auto replacement_config =
        std::make_shared<const erikslund::core::Config>(std::move(replacement_mutable_config));
    auto replacement_routing = erikslund::routing::make_routing_table(*replacement_config);
    replacement_routing->pools.front().backends.front()->healthy.store(true);
    state.publish(replacement_config, replacement_routing);

    auto replacement_client = erikslund::test::connect_loopback(listener_port);
    REQUIRE(replacement_client);
    REQUIRE(erikslund::test::wait_until(
        [&state] { return state.stats.snapshot().accepted_connections == 2; }, 1s));

    constexpr std::string_view original_request =
        "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"original\"]}\n";
    constexpr std::string_view replacement_request =
        "{\"id\":2,\"method\":\"mining.subscribe\",\"params\":[\"replacement\"]}\n";
    constexpr std::string_view response = "{\"id\":1,\"result\":true,\"error\":null}\n";

    REQUIRE(erikslund::test::send_all(original_client.get(), original_request));
    CHECK(erikslund::test::read_line(original_client.get()) == response);
    REQUIRE(erikslund::test::send_all(replacement_client.get(), replacement_request));
    CHECK(erikslund::test::read_line(replacement_client.get()) == response);

    REQUIRE(erikslund::test::wait_until(
        [&original_backend] { return original_backend.accepted() == 1; }, 1s));
    REQUIRE(erikslund::test::wait_until(
        [&replacement_backend] { return replacement_backend.accepted() == 1; }, 1s));
    CHECK(original_backend.request() == original_request);
    CHECK(replacement_backend.request() == replacement_request);

    edge.stop();
}

TEST_CASE("lowered process queue limit applies to sessions admitted before reload") {
    FakeBackend backend(2);
    REQUIRE(backend.port() != 0);
    const std::uint16_t listener_port = erikslund::test::unused_loopback_port();
    REQUIRE(listener_port != 0);

    auto original_mutable_config = reactor_config(listener_port, backend.port());
    original_mutable_config.limits.messages_per_second_per_connection = 1'000.0;
    original_mutable_config.limits.message_burst_per_connection = 16;
    original_mutable_config.limits.max_line_bytes = 1'024;
    original_mutable_config.limits.max_buffer_bytes = 2'048;
    original_mutable_config.limits.max_queued_bytes = 4'096;
    const auto original_config =
        std::make_shared<const erikslund::core::Config>(std::move(original_mutable_config));
    erikslund::core::ServiceState state;
    auto original_routing = erikslund::routing::make_routing_table(*original_config);
    original_routing->pools.front().backends.front()->healthy.store(true);
    state.publish(original_config, original_routing);

    erikslund::net::EdgeServer edge(*original_config, state);
    edge.start();

    auto client = erikslund::test::connect_loopback(listener_port);
    REQUIRE(client);
    constexpr std::string_view subscribe =
        "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n";
    REQUIRE(erikslund::test::send_all(client.get(), subscribe));
    REQUIRE(erikslund::test::wait_until([&backend] { return backend.accepted() == 1; }, 1s));

    auto replacement_mutable_config = *original_config;
    replacement_mutable_config.limits.max_line_bytes = 128;
    replacement_mutable_config.limits.max_buffer_bytes = 128;
    replacement_mutable_config.limits.max_queued_bytes = 128;
    const auto replacement_config =
        std::make_shared<const erikslund::core::Config>(std::move(replacement_mutable_config));
    auto replacement_routing = erikslund::routing::make_routing_table(
        *replacement_config, original_routing);
    state.publish(replacement_config, replacement_routing);

    const std::string authorize =
        "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"worker\",\"" +
        std::string(128, 'x') + "\"]}\n";
    REQUIRE(authorize.size() > replacement_config->limits.max_queued_bytes);
    REQUIRE(authorize.size() <= original_config->limits.max_line_bytes);
    REQUIRE(erikslund::test::send_all(client.get(), authorize));
    CHECK(erikslund::test::read_line(client.get()).empty());
    REQUIRE(erikslund::test::wait_until(
        [&state] { return state.stats.snapshot().rejected_queue_limit == 1; }, 1s));
    CHECK(state.stats.queued_bytes.load() == 0);
    CHECK(state.stats.queued_bytes_limit.load() == 128);
    REQUIRE(erikslund::test::wait_until(
        [&backend, subscribe] { return backend.request() == subscribe; }, 1s));

    edge.stop();
}
