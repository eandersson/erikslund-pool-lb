#pragma once
// SV1/SV1-TLS edge listeners and admitted connection lifecycle.

#include <functional>
#include <memory>
#include <thread>
#include <vector>

#include "core/service_state.hpp"

namespace erikslund::net {

class EdgeServer {
public:
    EdgeServer(const core::Config& config, core::ServiceState& state);
    ~EdgeServer();

    EdgeServer(const EdgeServer&) = delete;
    EdgeServer& operator=(const EdgeServer&) = delete;

    // on_worker_failure runs on the failing reactor thread when it stops early; the caller decides
    // whether losing a worker should stop the process.
    void start(const std::function<void()>& on_worker_failure = {});
    void stop();
    void reload_tls(const core::Config& config);

private:
    struct Runtime;

    core::ServiceState& state_;
    std::unique_ptr<Runtime> runtime_;
    std::vector<std::jthread> threads_;
};

} // namespace erikslund::net
