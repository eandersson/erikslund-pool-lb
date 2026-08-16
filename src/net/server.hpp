#pragma once
// SV1/SV1-TLS edge listeners and admitted connection lifecycle.

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

    void start();
    void stop();
    void reload_tls(const core::Config& config);

private:
    struct Runtime;

    core::ServiceState& state_;
    std::unique_ptr<Runtime> runtime_;
    std::vector<std::jthread> threads_;
};

} // namespace erikslund::net
