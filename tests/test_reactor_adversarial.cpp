// Adversarial edge-reactor coverage: reject hostile protocols before touching a pool.
#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include "core/config.hpp"
#include "core/service_state.hpp"
#include "net/server.hpp"
#include "routing/router.hpp"
#include "socket_test_utils.hpp"

using namespace std::chrono_literals;

namespace {

class SoftFileLimitRestore {
public:
    explicit SoftFileLimitRestore(rlimit original) : original_(original) {}

    ~SoftFileLimitRestore() {
        ::setrlimit(RLIMIT_NOFILE, &original_);
    }

    SoftFileLimitRestore(const SoftFileLimitRestore&) = delete;
    SoftFileLimitRestore& operator=(const SoftFileLimitRestore&) = delete;

private:
    rlimit original_{};
};

} // namespace

TEST_CASE("reactor rejects hostile first messages before opening an upstream socket") {
    auto backend_listener = erikslund::test::bind_loopback_listener();
    REQUIRE(backend_listener.port != 0);
    const std::uint16_t listener_port = erikslund::test::unused_loopback_port();
    REQUIRE(listener_port != 0);

    erikslund::core::Config mutable_config;
    mutable_config.listeners = {{.name = "adversarial-sv1",
                                 .address = "127.0.0.1:" + std::to_string(listener_port),
                                 .tls = false,
                                 .certificate_file = {},
                                 .private_key_file = {}}};
    mutable_config.pools = {{.name = "primary",
                             .backends = {{.name = "backend",
                                           .address = "127.0.0.1:" +
                                                      std::to_string(backend_listener.port),
                                           .health_address = {},
                                           .send_proxy_v2 = false}}}};
    mutable_config.active_pool = "primary";
    mutable_config.io_workers = 1;
    mutable_config.limits.max_connections = 64;
    mutable_config.limits.max_connections_per_ip = 64;
    mutable_config.limits.connections_per_second_per_ip = 1'000.0;
    mutable_config.limits.connection_burst_per_ip = 64;
    mutable_config.limits.global_connections_per_second = 1'000.0;
    mutable_config.limits.global_connection_burst = 64;
    mutable_config.limits.max_line_bytes = 128;
    const auto config =
        std::make_shared<const erikslund::core::Config>(std::move(mutable_config));

    erikslund::core::ServiceState state;
    auto routing = erikslund::routing::make_routing_table(*config);
    routing->pools.front().backends.front()->healthy.store(true);
    state.publish(config, routing);

    erikslund::net::EdgeServer edge(*config, state);
    edge.start();

    std::string excessive_nesting =
        R"({"id":1,"method":"mining.configure","params":)";
    excessive_nesting.append(40, '[');
    excessive_nesting += '0';
    excessive_nesting.append(40, ']');
    excessive_nesting += "}\n";
    const std::array<std::string, 8> payloads = {
        "GET / HTTP/1.1\r\n",
        "SSH-2.0-OpenSSH_9.0\r\n",
        std::string{"\x16\x03\x01\x00\x2a\n", 6},
        std::string{"\0\x01\x02\n", 4},
        "[]\n",
        "{\"id\":1,\"method\":true,\"params\":[]}\n",
        excessive_nesting,
        std::string(256, 'a') + '\n',
    };

    for (const std::string& payload : payloads) {
        auto client = erikslund::test::connect_loopback(listener_port);
        REQUIRE(client);
        REQUIRE(erikslund::test::send_all(client.get(), payload));
        CHECK(erikslund::test::read_line(client.get()).empty());
    }

    REQUIRE(erikslund::test::wait_until(
        [&state, &payloads] {
            return state.stats.snapshot().rejected_protocol == payloads.size();
        },
        1s));
    pollfd descriptor{backend_listener.socket.get(), POLLIN, 0};
    CHECK(::poll(&descriptor, 1, 100) == 0);
    edge.stop();
    CHECK(state.stats.active_connections.load() == 0);
    CHECK(state.stats.queued_bytes.load() == 0);
}

TEST_CASE("reactor pauses and rearms a listener after file descriptor exhaustion") {
    auto backend_listener = erikslund::test::bind_loopback_listener();
    REQUIRE(backend_listener.port != 0);
    const std::uint16_t listener_port = erikslund::test::unused_loopback_port();
    REQUIRE(listener_port != 0);

    erikslund::core::Config mutable_config;
    mutable_config.listeners = {{.name = "resource-sv1",
                                 .address = "127.0.0.1:" + std::to_string(listener_port),
                                 .tls = false,
                                 .certificate_file = {},
                                 .private_key_file = {}}};
    mutable_config.pools = {{.name = "primary",
                             .backends = {{.name = "backend",
                                           .address = "127.0.0.1:" +
                                                      std::to_string(backend_listener.port),
                                           .health_address = {},
                                           .send_proxy_v2 = false}}}};
    mutable_config.active_pool = "primary";
    mutable_config.io_workers = 1;
    mutable_config.limits.max_connections = 16;
    mutable_config.limits.max_connections_per_ip = 16;
    mutable_config.limits.connections_per_second_per_ip = 1'000.0;
    mutable_config.limits.connection_burst_per_ip = 16;
    mutable_config.limits.global_connections_per_second = 1'000.0;
    mutable_config.limits.global_connection_burst = 16;
    const auto config =
        std::make_shared<const erikslund::core::Config>(std::move(mutable_config));

    erikslund::core::ServiceState state;
    auto routing = erikslund::routing::make_routing_table(*config);
    routing->pools.front().backends.front()->healthy.store(true);
    state.publish(config, routing);
    erikslund::net::EdgeServer edge(*config, state);
    edge.start();

    erikslund::net::UniqueFd client(
        ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP));
    REQUIRE(client);
    rlimit original_limit{};
    REQUIRE(::getrlimit(RLIMIT_NOFILE, &original_limit) == 0);
    SoftFileLimitRestore restore(original_limit);
    rlimit constrained_limit = original_limit;
    constrained_limit.rlim_cur =
        std::min(original_limit.rlim_cur, static_cast<rlim_t>(128));
    REQUIRE(::setrlimit(RLIMIT_NOFILE, &constrained_limit) == 0);

    std::vector<erikslund::net::UniqueFd> fillers;
    while (true) {
        erikslund::net::UniqueFd filler(::open("/dev/null", O_RDONLY | O_CLOEXEC));
        if (!filler) {
            REQUIRE((errno == EMFILE || errno == ENFILE));
            break;
        }
        fillers.push_back(std::move(filler));
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(listener_port);
    const auto batches_before = state.stats.snapshot().event_batches;
    REQUIRE(::connect(client.get(), reinterpret_cast<const sockaddr*>(&address),
                      sizeof(address)) == 0);
    REQUIRE(erikslund::test::wait_until(
        [&state, batches_before] {
            return state.stats.snapshot().event_batches > batches_before;
        },
        1s));
    CHECK(state.stats.snapshot().accepted_connections == 0);
    const auto batches_while_paused = state.stats.snapshot().event_batches;
    std::this_thread::sleep_for(100ms);
    CHECK(state.stats.snapshot().event_batches <= batches_while_paused + 2);

    constexpr std::size_t kDescriptorsToRelease = 16;
    for (std::size_t count = 0; count < kDescriptorsToRelease && !fillers.empty(); ++count)
        fillers.pop_back();
    REQUIRE(erikslund::test::wait_until(
        [&state] { return state.stats.snapshot().accepted_connections == 1; }, 2s));

    fillers.clear();
    edge.stop();
    CHECK(state.stats.active_connections.load() == 0);
    CHECK(state.stats.queued_bytes.load() == 0);
}
