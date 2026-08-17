#pragma once
// Loopback socket helpers for kernel-level unit tests.

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "net/unique_fd.hpp"

namespace erikslund::test {

struct BoundListener {
    net::UniqueFd socket;
    std::uint16_t port;
};

inline BoundListener bind_loopback_listener(bool nonblocking = false) {
    const int flags = SOCK_STREAM | SOCK_CLOEXEC | (nonblocking ? SOCK_NONBLOCK : 0);
    net::UniqueFd socket(::socket(AF_INET, flags, IPPROTO_TCP));
    if (!socket)
        return {};
    const int enabled = 1;
    ::setsockopt(socket.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(socket.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0 ||
        ::listen(socket.get(), 32) < 0)
        return {};
    socklen_t length = sizeof(address);
    if (::getsockname(socket.get(), reinterpret_cast<sockaddr*>(&address), &length) < 0)
        return {};
    return {.socket = std::move(socket), .port = ntohs(address.sin_port)};
}

inline std::uint16_t unused_loopback_port() {
    return bind_loopback_listener().port;
}

inline net::UniqueFd connect_loopback(std::uint16_t port, int receive_buffer_bytes = 0) {
    net::UniqueFd socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP));
    if (!socket)
        return {};
    timeval timeout{.tv_sec = 4, .tv_usec = 0};
    ::setsockopt(socket.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(socket.get(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (receive_buffer_bytes > 0)
        ::setsockopt(socket.get(), SOL_SOCKET, SO_RCVBUF, &receive_buffer_bytes,
                     sizeof(receive_buffer_bytes));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (::connect(socket.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0)
        return {};
    return socket;
}

inline bool send_all(int socket, std::string_view bytes) {
    while (!bytes.empty()) {
        const ssize_t sent = ::send(socket, bytes.data(), bytes.size(), MSG_NOSIGNAL);
        if (sent <= 0)
            return false;
        bytes.remove_prefix(static_cast<std::size_t>(sent));
    }
    return true;
}

inline std::string read_line(int socket) {
    std::string line;
    char character = '\0';
    while (::recv(socket, &character, 1, 0) == 1) {
        line.push_back(character);
        if (character == '\n')
            break;
    }
    return line;
}

inline std::string read_to_close(int socket) {
    std::string output;
    char buffer[1'024]{};
    while (true) {
        const ssize_t received = ::recv(socket, buffer, sizeof(buffer), 0);
        if (received <= 0)
            break;
        output.append(buffer, static_cast<std::size_t>(received));
    }
    return output;
}

template <typename Predicate>
bool wait_until(Predicate predicate, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return predicate();
}

} // namespace erikslund::test
