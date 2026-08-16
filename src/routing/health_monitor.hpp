#pragma once
// HTTP readiness checks with a generic TCP-connect fallback.

#include <cstdint>
#include <memory>
#include <stop_token>

#include "core/service_state.hpp"

namespace erikslund::routing {

class HealthMonitor {
public:
    explicit HealthMonitor(core::ServiceState& state) : state_(state) {}

    void run(const std::stop_token& stop_token);

private:
    void check_backend(const std::shared_ptr<BackendState>& backend,
                       const core::HealthConfig& config, const std::stop_token& stop_token);

    core::ServiceState& state_;
    std::uint64_t address_sequence_ = 0;
};

} // namespace erikslund::routing
