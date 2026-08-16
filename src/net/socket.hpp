#pragma once
// Nonblocking TCP listener, connect, and deadline helpers.

#include <chrono>
#include <stop_token>

#include "net/endpoint.hpp"
#include "net/unique_fd.hpp"

namespace erikslund::net {

using SteadyClock = std::chrono::steady_clock;

UniqueFd create_listener(const SocketAddress& address, int backlog, bool reuse_port = false);

struct ConnectStart {
    UniqueFd socket;
    bool connected = false;
};

ConnectStart start_connect(const SocketAddress& address,
                           const SocketAddress* source_address = nullptr);
UniqueFd connect_tcp(const SocketAddress& address, std::chrono::milliseconds timeout,
                     const std::stop_token& stop_token = {});
bool wait_fd(int file_descriptor, short events, SteadyClock::time_point deadline,
             const std::stop_token& stop_token = {});
void configure_stream_socket(int file_descriptor);

} // namespace erikslund::net
