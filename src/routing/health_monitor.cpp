#include "routing/health_monitor.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <string_view>

#include <poll.h>
#include <sys/socket.h>

#include "core/logging.hpp"
#include "net/socket.hpp"

namespace erikslund::routing {

namespace {

constexpr std::string_view kHealthRequest =
    "GET /health HTTP/1.1\r\nHost: pool-backend\r\nConnection: close\r\n\r\n";
constexpr std::size_t kMaximumStatusLineBytes = 512;
constexpr std::size_t kStatusLineTerminatorBytes = 2;

std::optional<bool> healthy_status(std::string_view response) {
    const std::size_t line_end = response.find("\r\n");
    if (line_end == std::string_view::npos)
        return std::nullopt;
    const std::string_view status_line = response.substr(0, line_end);
    return status_line.starts_with("HTTP/1.1 200 ") ||
           status_line.starts_with("HTTP/1.0 200 ");
}

std::chrono::milliseconds timeout_until(net::SteadyClock::time_point deadline) {
    const auto now = net::SteadyClock::now();
    if (now >= deadline)
        return std::chrono::milliseconds::zero();
    return std::chrono::ceil<std::chrono::milliseconds>(deadline - now);
}

bool send_health_request(int socket, net::SteadyClock::time_point deadline,
                         const std::stop_token& stop_token) {
    std::string_view remaining = kHealthRequest;
    while (!remaining.empty()) {
        if (!net::wait_fd(socket, POLLOUT, deadline, stop_token))
            return false;
        const ssize_t sent = ::send(socket, remaining.data(), remaining.size(), MSG_NOSIGNAL);
        if (sent > 0) {
            remaining.remove_prefix(static_cast<std::size_t>(sent));
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            continue;
        return false;
    }
    return true;
}

bool read_healthy_status(int socket, net::SteadyClock::time_point deadline,
                         const std::stop_token& stop_token) {
    std::array<char, kMaximumStatusLineBytes + kStatusLineTerminatorBytes> response{};
    std::size_t response_size = 0;
    while (response_size < response.size()) {
        const ssize_t received =
            ::recv(socket, response.data() + response_size, response.size() - response_size, 0);
        if (received > 0) {
            response_size += static_cast<std::size_t>(received);
            if (const auto status = healthy_status({response.data(), response_size}))
                return *status;
            continue;
        }
        if (received == 0)
            return false;
        if (errno == EINTR)
            continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return false;
        if (!net::wait_fd(socket, POLLIN, deadline, stop_token)) {
            // A server may close immediately after its response, causing POLLIN|POLLHUP.
            const ssize_t final_received = ::recv(socket, response.data() + response_size,
                                                  response.size() - response_size, 0);
            if (final_received <= 0)
                return false;
            response_size += static_cast<std::size_t>(final_received);
            const auto status = healthy_status({response.data(), response_size});
            return status.value_or(false);
        }
    }
    return false;
}

bool check_http_address(const net::SocketAddress& address,
                        net::SteadyClock::time_point deadline,
                        const std::stop_token& stop_token) {
    const auto timeout = timeout_until(deadline);
    if (timeout == std::chrono::milliseconds::zero())
        return false;
    net::UniqueFd socket = net::connect_tcp(address, timeout, stop_token);
    return socket && send_health_request(socket.get(), deadline, stop_token) &&
           read_healthy_status(socket.get(), deadline, stop_token);
}

bool check_tcp_address(const net::SocketAddress& address,
                       net::SteadyClock::time_point deadline,
                       const std::stop_token& stop_token) {
    const auto timeout = timeout_until(deadline);
    return timeout > std::chrono::milliseconds::zero() &&
           static_cast<bool>(net::connect_tcp(address, timeout, stop_token));
}

} // namespace

void HealthMonitor::check_backend(const std::shared_ptr<BackendState>& backend,
                                  const core::HealthConfig& config,
                                  const std::stop_token& stop_token) {
    bool reachable = false;
    const bool use_http = !backend->health_socket_addresses.empty();
    const auto& addresses = use_http ? backend->health_socket_addresses : backend->socket_addresses;
    const std::size_t address_count = addresses.size();
    const std::size_t first_address =
        address_count == 0 ? 0 : address_sequence_++ % address_count;
    const auto overall_deadline =
        net::SteadyClock::now() +
        std::chrono::milliseconds(config.connect_timeout_milliseconds);
    for (std::size_t offset = 0; offset < address_count && !stop_token.stop_requested(); ++offset) {
        const auto now = net::SteadyClock::now();
        if (now >= overall_deadline)
            break;
        const std::size_t attempts_remaining = address_count - offset;
        const auto attempt_deadline =
            now + (overall_deadline - now) / attempts_remaining;
        const auto& address = addresses[(first_address + offset) % address_count];
        const bool healthy =
            use_http ? check_http_address(address, attempt_deadline, stop_token)
                     : check_tcp_address(address, attempt_deadline, stop_token);
        if (healthy) {
            reachable = true;
            break;
        }
    }
    const bool was_healthy = backend->healthy.load(std::memory_order_relaxed);
    if (reachable) {
        backend->consecutive_failures.store(0, std::memory_order_relaxed);
        const int successes =
            backend->consecutive_successes.fetch_add(1, std::memory_order_relaxed) + 1;
        if (!was_healthy && successes >= config.rise_checks) {
            backend->healthy.store(true, std::memory_order_relaxed);
            core::log::info("Backend {}/{} is healthy", backend->pool, backend->name);
        }
    } else {
        backend->consecutive_successes.store(0, std::memory_order_relaxed);
        const int failures =
            backend->consecutive_failures.fetch_add(1, std::memory_order_relaxed) + 1;
        if (was_healthy && failures >= config.fall_checks) {
            backend->healthy.store(false, std::memory_order_relaxed);
            core::log::warning("Backend {}/{} is unhealthy", backend->pool, backend->name);
        }
    }
}

void HealthMonitor::run(const std::stop_token& stop_token) {
    std::condition_variable_any wake;
    std::mutex wait_mutex;
    while (!stop_token.stop_requested()) {
        const auto runtime = state_.runtime.load(std::memory_order_acquire);
        const auto& table = runtime->routing;
        for (const PoolState& pool : table->pools)
            for (const auto& backend : pool.backends) {
                if (stop_token.stop_requested())
                    return;
                check_backend(backend, table->health, stop_token);
            }
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(table->health.interval_seconds);
        std::unique_lock lock(wait_mutex);
        wake.wait_until(lock, stop_token, deadline, [] { return false; });
    }
}

} // namespace erikslund::routing
