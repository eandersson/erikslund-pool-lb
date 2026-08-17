#include "net/socket.hpp"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <format>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>

#include "core/errors.hpp"

namespace erikslund::net {

namespace {

constexpr auto kDeadPeerTimeout = std::chrono::milliseconds(90'000);

int remaining_milliseconds(SteadyClock::time_point deadline) {
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - SteadyClock::now()).count();
    if (remaining <= 0)
        return 0;
    return static_cast<int>(std::min<std::int64_t>(remaining, INT_MAX));
}

} // namespace

void configure_stream_socket(int file_descriptor) {
    const int enabled = 1;
    ::setsockopt(file_descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
    ::setsockopt(file_descriptor, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled));
    const unsigned int user_timeout_milliseconds = kDeadPeerTimeout.count();
    ::setsockopt(file_descriptor, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_milliseconds,
                 sizeof(user_timeout_milliseconds));
}

UniqueFd create_listener(const SocketAddress& address, int backlog, bool reuse_port) {
    UniqueFd socket(::socket(address.family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP));
    if (!socket)
        throw core::IoError(std::format("socket: {}", std::strerror(errno)));
    const int enabled = 1;
    if (::setsockopt(socket.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) < 0)
        throw core::IoError(std::format("setsockopt(SO_REUSEADDR): {}", std::strerror(errno)));
    if (reuse_port &&
        ::setsockopt(socket.get(), SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled)) < 0)
        throw core::IoError(std::format("setsockopt(SO_REUSEPORT): {}", std::strerror(errno)));
    if (address.family == AF_INET6) {
        const int disabled = 0;
        ::setsockopt(socket.get(), IPPROTO_IPV6, IPV6_V6ONLY, &disabled, sizeof(disabled));
    }
    if (::bind(socket.get(), reinterpret_cast<const sockaddr*>(&address.value), address.length) < 0)
        throw core::IoError(std::format("bind: {}", std::strerror(errno)));
    if (::listen(socket.get(), backlog) < 0)
        throw core::IoError(std::format("listen: {}", std::strerror(errno)));
    return socket;
}

ConnectStart start_connect(const SocketAddress& address,
                           const SocketAddress* source_address) {
    UniqueFd socket(::socket(address.family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP));
    if (!socket)
        return {};
    configure_stream_socket(socket.get());
    if (source_address != nullptr) {
        if (source_address->family != address.family)
            return {};
#ifdef IP_BIND_ADDRESS_NO_PORT
        if (address.family == AF_INET) {
            const int enabled = 1;
            // Best effort: older kernels may not support deferred ephemeral-port allocation.
            ::setsockopt(socket.get(), IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &enabled,
                         sizeof(enabled));
        }
#endif
        if (::bind(socket.get(), reinterpret_cast<const sockaddr*>(&source_address->value),
                   source_address->length) < 0)
            return {};
    }
    const int result =
        ::connect(socket.get(), reinterpret_cast<const sockaddr*>(&address.value), address.length);
    if (result == 0)
        return {.socket = std::move(socket), .connected = true};
    if (errno != EINPROGRESS)
        return {};
    return {.socket = std::move(socket), .connected = false};
}

bool wait_fd(int file_descriptor, short events, SteadyClock::time_point deadline,
             const std::stop_token& stop_token) {
    while (!stop_token.stop_requested()) {
        const int remaining = remaining_milliseconds(deadline);
        if (remaining <= 0)
            return false;
        pollfd descriptor{file_descriptor, events, 0};
        const int result = ::poll(&descriptor, 1, std::min(remaining, 250));
        if (result > 0)
            return (descriptor.revents & events) != 0 &&
                   (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0;
        if (result < 0 && errno != EINTR)
            return false;
    }
    return false;
}

UniqueFd connect_tcp(const SocketAddress& address, std::chrono::milliseconds timeout,
                     const std::stop_token& stop_token) {
    ConnectStart started = start_connect(address);
    if (!started.socket)
        return {};
    if (started.connected)
        return std::move(started.socket);
    if (!wait_fd(started.socket.get(), POLLOUT, SteadyClock::now() + timeout, stop_token))
        return {};
    int socket_error = 0;
    socklen_t error_length = sizeof(socket_error);
    if (::getsockopt(started.socket.get(), SOL_SOCKET, SO_ERROR, &socket_error, &error_length) < 0 ||
        socket_error != 0)
        return {};
    return std::move(started.socket);
}

} // namespace erikslund::net
