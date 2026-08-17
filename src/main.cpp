#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <format>
#include <limits>
#include <memory>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>

#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>

#ifdef HAVE_MIMALLOC
#include <mimalloc.h>
#endif

#include "api/http_server.hpp"
#include "core/config.hpp"
#include "core/errors.hpp"
#include "core/logging.hpp"
#include "core/service_state.hpp"
#include "core/version.hpp"
#include "net/server.hpp"
#include "net/socket.hpp"
#include "routing/health_monitor.hpp"
#include "routing/router.hpp"

namespace {

constexpr std::string_view kDefaultConfigPath = "/etc/erikslund-pool-lb/pool-lb.yml";
constexpr auto kMainLoopInterval = std::chrono::milliseconds(200);

std::atomic<bool> stop_requested{false};
std::atomic<bool> reload_requested{false};

extern "C" void handle_signal(int signal_number) {
    if (signal_number == SIGHUP)
        reload_requested.store(true, std::memory_order_relaxed);
    else
        stop_requested.store(true, std::memory_order_relaxed);
}

std::string config_path_from(int argument_count, char** arguments) {
    if (const char* environment = std::getenv("ERIKSLUND_POOL_LB_CONFIG"))
        if (*environment != '\0')
            return environment;
    if (argument_count == 1)
        return std::string(kDefaultConfigPath);
    if (argument_count == 3 && std::string_view(arguments[1]) == "--config")
        return arguments[2];
    throw erikslund::core::ConfigError(
        "usage: erikslund-pool-lb [--config PATH] | --health-check HOST:PORT");
}

bool run_health_check(std::string_view address) {
    constexpr auto kHealthCheckTimeout = std::chrono::seconds(3);
    const auto deadline = erikslund::net::SteadyClock::now() + kHealthCheckTimeout;
    const auto addresses = erikslund::net::resolve_endpoints(
        erikslund::net::parse_endpoint(std::string(address)));
    erikslund::net::UniqueFd socket;
    for (const erikslund::net::SocketAddress& candidate : addresses) {
        const auto now = erikslund::net::SteadyClock::now();
        if (now >= deadline)
            break;
        const auto remaining =
            std::chrono::ceil<std::chrono::milliseconds>(deadline - now);
        socket = erikslund::net::connect_tcp(candidate, remaining);
        if (socket)
            break;
    }
    if (!socket)
        return false;
    constexpr std::string_view request =
        "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    std::string_view remaining = request;
    while (!remaining.empty()) {
        if (!erikslund::net::wait_fd(socket.get(), POLLOUT, deadline))
            return false;
        const ssize_t sent =
            ::send(socket.get(), remaining.data(), remaining.size(), MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            return false;
        }
        remaining.remove_prefix(static_cast<std::size_t>(sent));
    }
    if (!erikslund::net::wait_fd(socket.get(), POLLIN, deadline))
        return false;
    std::array<char, 64> response{};
    const ssize_t received = ::recv(socket.get(), response.data(), response.size(), 0);
    return received > 0 &&
           std::string_view(response.data(), static_cast<std::size_t>(received))
               .starts_with("HTTP/1.1 200 ");
}

void validate_file_descriptor_limit(const erikslund::core::Config& config) {
    constexpr std::uint64_t kDescriptorHeadroom = 4'096;
    rlimit limit{};
    if (::getrlimit(RLIMIT_NOFILE, &limit) != 0)
        throw erikslund::core::ConfigError("cannot read RLIMIT_NOFILE");
    if (config.limits.max_connections >
        (std::numeric_limits<std::uint64_t>::max() - kDescriptorHeadroom) / 2)
        throw erikslund::core::ConfigError("limits.max_connections is too large");
    const std::uint64_t required =
        static_cast<std::uint64_t>(config.limits.max_connections) * 2 + kDescriptorHeadroom;
    if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < required)
        throw erikslund::core::ConfigError(
            std::format("RLIMIT_NOFILE is {} but at least {} is required for {} sessions",
                        limit.rlim_cur, required, config.limits.max_connections));
}

} // namespace

int main(int argument_count, char** arguments) {
    using namespace erikslund;
    try {
        if (argument_count == 3 && std::string_view(arguments[1]) == "--health-check")
            return run_health_check(arguments[2]) ? 0 : 1;
        const std::string config_path = config_path_from(argument_count, arguments);
        auto config = std::make_shared<const core::Config>(core::Config::from_file(config_path));
        validate_file_descriptor_limit(*config);
        auto routing = routing::make_routing_table(*config);

        core::ServiceState state;
        state.publish(config, routing);

        std::signal(SIGINT, handle_signal);
        std::signal(SIGTERM, handle_signal);
        std::signal(SIGHUP, handle_signal);
        std::signal(SIGPIPE, SIG_IGN);

        core::log::info("erikslund-pool-lb v{} starting", core::kVersion);
#ifdef HAVE_MIMALLOC
        core::log::info("allocator: mimalloc {}", mi_version());
#endif

        net::EdgeServer edge(*config, state);
        api::HttpServer http(*config, state);
        routing::HealthMonitor health(state);
        edge.start([] { stop_requested.store(true, std::memory_order_relaxed); });
        std::jthread health_thread([&health](const std::stop_token& token) {
            try {
                health.run(token);
            } catch (const std::exception& error) {
                core::log::error("Health thread crashed: {}", error.what());
                stop_requested.store(true, std::memory_order_relaxed);
            }
        });
        std::jthread http_thread([&http](const std::stop_token& token) {
            try {
                http.run(token);
            } catch (const std::exception& error) {
                core::log::error("HTTP thread crashed: {}", error.what());
                stop_requested.store(true, std::memory_order_relaxed);
            }
        });
        core::log::info("Observability ready on {}", config->api_address);

        while (!stop_requested.load(std::memory_order_relaxed)) {
            if (reload_requested.exchange(false, std::memory_order_relaxed)) {
                try {
                    auto replacement =
                        std::make_shared<const core::Config>(core::Config::from_file(config_path));
                    validate_file_descriptor_limit(*replacement);
                    const auto changes = config->restart_required_changes(*replacement);
                    if (!changes.empty()) {
                        std::string names;
                        for (const std::string& change : changes) {
                            if (!names.empty())
                                names += ", ";
                            names += change;
                        }
                        core::log::warning("Configuration reload rejected; {} require a restart",
                                           names);
                    } else {
                        auto replacement_routing = routing::make_routing_table(
                            *replacement,
                            state.runtime.load(std::memory_order_acquire)->routing);
                        edge.reload_tls(*replacement);
                        state.publish(replacement, replacement_routing);
                        config = std::move(replacement);
                        core::log::info("Configuration reloaded; new sessions use pool {}",
                                        config->active_pool);
                    }
                } catch (const std::exception& error) {
                    core::log::warning("Configuration reload failed; keeping current settings: {}",
                                       error.what());
                }
            }
            std::this_thread::sleep_for(kMainLoopInterval);
        }

        core::log::info("Shutdown requested");
        edge.stop();
        http_thread.request_stop();
        health_thread.request_stop();
        return 0;
    } catch (const std::exception& error) {
        erikslund::core::log::error("Startup failed: {}", error.what());
        return 1;
    }
}
