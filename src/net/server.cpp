#include "net/server.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <exception>
#include <fstream>
#include <limits>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <sched.h>

#include "core/errors.hpp"
#include "core/logging.hpp"
#include "net/endpoint.hpp"
#include "net/reactor.hpp"
#include "net/tls.hpp"

namespace erikslund::net {

namespace {

constexpr unsigned int kMaximumAutomaticWorkers = 32;
constexpr std::size_t kSessionCapacitySkewPercent = 25;
constexpr std::size_t kWholePercent = 100;

struct LoadedTlsContexts {
    std::vector<SslContext> contexts;
    std::shared_ptr<const core::TlsCertificateStatuses> certificates;
};

LoadedTlsContexts load_tls_contexts(const core::Config& config) {
    LoadedTlsContexts loaded;
    loaded.contexts.reserve(config.listeners.size());
    core::TlsCertificateStatuses certificates;
    for (const core::ListenerConfig& listener : config.listeners) {
        if (listener.tls) {
            SslContext context =
                create_server_context(listener.certificate_file, listener.private_key_file);
            certificates.push_back({
                .listener_name = listener.name,
                .expiry_timestamp_seconds = certificate_expiry_timestamp_seconds(context),
            });
            loaded.contexts.push_back(std::move(context));
        } else {
            loaded.contexts.emplace_back();
        }
    }
    loaded.certificates =
        std::make_shared<const core::TlsCertificateStatuses>(std::move(certificates));
    return loaded;
}

std::size_t worker_count(const core::Config& config) {
    if (config.io_workers > 0)
        return static_cast<std::size_t>(config.io_workers);

    unsigned int available = std::max(std::thread::hardware_concurrency(), 1u);
    cpu_set_t affinity{};
    if (::sched_getaffinity(0, sizeof(affinity), &affinity) == 0) {
        const int affinity_count = CPU_COUNT(&affinity);
        if (affinity_count > 0)
            available = std::min(available, static_cast<unsigned int>(affinity_count));
    }

    std::ifstream cpu_max("/sys/fs/cgroup/cpu.max");
    std::string quota_text;
    std::string period_text;
    if (cpu_max >> quota_text >> period_text && quota_text != "max") {
        std::uint64_t quota = 0;
        std::uint64_t period = 0;
        const auto parse = [](const std::string& text, std::uint64_t& output) {
            const char* const end = text.data() + text.size();
            const auto [pointer, error] = std::from_chars(text.data(), end, output);
            return error == std::errc{} && pointer == end;
        };
        if (parse(quota_text, quota) && parse(period_text, period) && quota > 0 && period > 0) {
            const std::uint64_t quota_workers =
                quota / period + static_cast<std::uint64_t>(quota % period != 0);
            available = std::min(
                available,
                static_cast<unsigned int>(std::min<std::uint64_t>(
                    quota_workers, std::numeric_limits<unsigned int>::max())));
        }
    }
    return std::min(available, kMaximumAutomaticWorkers);
}

} // namespace

struct EdgeServer::Runtime {
    std::vector<ReactorListener> listener_templates;
    RateLimiter rate_limiter;
    TlsContextStore tls_contexts;
    std::vector<std::unique_ptr<Reactor>> reactors;
};

EdgeServer::EdgeServer(const core::Config& config, core::ServiceState& state)
    : state_(state), runtime_(std::make_unique<Runtime>()) {
    for (const core::ListenerConfig& listener_config : config.listeners) {
        const auto addresses = resolve_endpoints(parse_endpoint(listener_config.address), true);
        ReactorListener listener{
            // One logical listener binds the resolver's preferred address. IPv6 listeners accept
            // IPv4-mapped peers as well; backend connections retain every resolved address.
            .socket_address = addresses.front(),
        };
        runtime_->listener_templates.push_back(listener);
    }
    LoadedTlsContexts loaded_tls = load_tls_contexts(config);
    runtime_->tls_contexts.publish(std::move(loaded_tls.contexts));
    state_.tls_certificates.store(std::move(loaded_tls.certificates), std::memory_order_release);
    const std::size_t count = worker_count(config);
    state_.stats.initialize_workers(count);
    runtime_->reactors.reserve(count);
    const std::size_t sessions_per_worker =
        (config.limits.max_connections + count - 1) / count;
    const std::size_t expected_sessions =
        sessions_per_worker +
        sessions_per_worker * kSessionCapacitySkewPercent / kWholePercent;
    for (std::size_t worker_index = 0; worker_index < count; ++worker_index)
        runtime_->reactors.push_back(std::make_unique<Reactor>(
            runtime_->listener_templates, runtime_->tls_contexts, state_,
            runtime_->rate_limiter, state_.stats.worker(worker_index), expected_sessions));
    state_.stats.io_workers.store(count, std::memory_order_relaxed);
}

EdgeServer::~EdgeServer() {
    stop();
}

void EdgeServer::start() {
    if (!threads_.empty())
        return;
    threads_.reserve(runtime_->reactors.size());
    for (const auto& reactor : runtime_->reactors)
        threads_.emplace_back([reactor = reactor.get()](const std::stop_token& stop_token) {
            try {
                reactor->run(stop_token);
            } catch (const std::exception& error) {
                core::log::error("I/O reactor stopped: {}", error.what());
            }
        });
    const auto runtime = state_.runtime.load(std::memory_order_acquire);
    for (const core::ListenerConfig& listener : runtime->config->listeners)
        core::log::info("Listener {} ready on {} ({})", listener.name, listener.address,
                        listener.tls ? "TLS" : "plaintext");
    core::log::info("I/O reactors: {} fixed workers for up to {} sessions",
                    runtime_->reactors.size(), runtime->config->limits.max_connections);
}

void EdgeServer::stop() {
    for (auto& thread : threads_)
        thread.request_stop();
    threads_.clear();
}

void EdgeServer::reload_tls(const core::Config& config) {
    const std::size_t tls_listener_count = static_cast<std::size_t>(
        std::ranges::count_if(config.listeners,
                              [](const core::ListenerConfig& listener) { return listener.tls; }));
    if (tls_listener_count == 0)
        return;
    try {
        LoadedTlsContexts replacement = load_tls_contexts(config);
        if (replacement.contexts.size() != runtime_->listener_templates.size())
            throw core::ConfigError("listener topology changed during TLS reload");
        runtime_->tls_contexts.publish(std::move(replacement.contexts));
        state_.tls_certificates.store(std::move(replacement.certificates),
                                      std::memory_order_release);
        state_.stats.tls_reload_successes.fetch_add(1, std::memory_order_relaxed);
        core::log::info("TLS credentials reloaded for {} listener(s)", tls_listener_count);
    } catch (...) {
        state_.stats.tls_reload_failures.fetch_add(1, std::memory_order_relaxed);
        throw;
    }
}

} // namespace erikslund::net
