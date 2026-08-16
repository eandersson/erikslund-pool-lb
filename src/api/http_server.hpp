#pragma once
// Internal status, Prometheus, and health routes served by erikslund-http-embedded.

#include <stop_token>

#include <erikslund/http/server.hpp>

#include "core/service_state.hpp"

namespace erikslund::api {

class HttpServer {
public:
    HttpServer(const core::Config& config, core::ServiceState& state);

    void run(const std::stop_token& stop_token);

private:
    http::Server server_;
};

} // namespace erikslund::api
