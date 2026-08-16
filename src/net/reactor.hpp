#pragma once
// Fixed-thread epoll reactor for high-concurrency SV1 and SV1/TLS sessions.

#include <memory>
#include <stop_token>
#include <vector>

#include "core/config.hpp"
#include "core/service_state.hpp"
#include "net/endpoint.hpp"
#include "net/rate_limiter.hpp"
#include "net/tls.hpp"

namespace erikslund::net {

struct ReactorListener {
    SocketAddress socket_address;
};

class Reactor {
public:
    Reactor(const std::vector<ReactorListener>& listeners, TlsContextStore& tls_contexts,
            core::ServiceState& state, RateLimiter& rate_limiter,
            core::WorkerStats& worker_stats, std::size_t expected_sessions);
    ~Reactor();

    Reactor(const Reactor&) = delete;
    Reactor& operator=(const Reactor&) = delete;

    void run(const std::stop_token& stop_token);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace erikslund::net
