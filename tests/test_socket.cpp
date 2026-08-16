#include <doctest/doctest.h>

#include <chrono>
#include <string>
#include <string_view>

#include <poll.h>
#include <sys/socket.h>

#include "net/endpoint.hpp"
#include "net/socket.hpp"
#include "net/unique_fd.hpp"
#include "socket_test_utils.hpp"

using namespace std::chrono_literals;

namespace {

std::string connect_from(const erikslund::test::BoundListener& listener,
                         std::string_view source_host) {
    const auto destinations = erikslund::net::resolve_endpoints(
        erikslund::net::parse_endpoint("127.0.0.1:" + std::to_string(listener.port)));
    REQUIRE(destinations.size() == 1);
    const auto source = erikslund::net::resolve_numeric_bind_host(source_host);
    auto started = erikslund::net::start_connect(destinations.front(), &source);
    REQUIRE(started.socket);
    if (!started.connected) {
        REQUIRE(erikslund::net::wait_fd(started.socket.get(), POLLOUT,
                                        erikslund::net::SteadyClock::now() + 1s));
        int socket_error = 0;
        socklen_t error_length = sizeof(socket_error);
        REQUIRE(::getsockopt(started.socket.get(), SOL_SOCKET, SO_ERROR, &socket_error,
                             &error_length) == 0);
        REQUIRE(socket_error == 0);
    }

    sockaddr_storage peer{};
    socklen_t peer_length = sizeof(peer);
    erikslund::net::UniqueFd accepted(
        ::accept4(listener.socket.get(), reinterpret_cast<sockaddr*>(&peer), &peer_length,
                  SOCK_CLOEXEC));
    REQUIRE(accepted);
    return erikslund::net::address_host(peer);
}

} // namespace

TEST_CASE("nonblocking connects bind the requested outbound source address") {
    const auto listener = erikslund::test::bind_loopback_listener();
    REQUIRE(listener.socket);

    CHECK(connect_from(listener, "127.0.0.2") == "127.0.0.2");
    CHECK(connect_from(listener, "127.0.0.3") == "127.0.0.3");
}
