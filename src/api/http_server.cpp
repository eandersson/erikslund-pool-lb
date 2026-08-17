#include "api/http_server.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include <unistd.h>

#include <erikslund/http/request.hpp>
#include <erikslund/http/response.hpp>
#include <erikslund/http/router.hpp>
#include <erikslund/http/status.hpp>

#include "core/logging.hpp"
#include "core/version.hpp"
#include "net/endpoint.hpp"
#include "routing/router.hpp"
#include "stratum/validator.hpp"

namespace erikslund::api {

namespace {

constexpr int kListenBacklog = 64;
constexpr std::size_t kMaximumRequestBytes = 4'096;
constexpr std::size_t kMaximumConnections = 128;
constexpr auto kRequestTimeout = std::chrono::seconds(3);
constexpr auto kCertificateExpiryWarning = std::chrono::days(30);
constexpr unsigned kHttpWorkers = 1;
constexpr double kNanosecondsPerMillisecond = 1'000'000.0;

std::string html_escape(std::string_view value) {
    std::string output;
    output.reserve(value.size());
    for (const char character : value) {
        switch (character) {
        case '&':
            output += "&amp;";
            break;
        case '<':
            output += "&lt;";
            break;
        case '>':
            output += "&gt;";
            break;
        case '"':
            output += "&quot;";
            break;
        case '\'':
            output += "&#39;";
            break;
        default:
            output.push_back(character);
        }
    }
    return output;
}

std::string prometheus_label(std::string_view value) {
    std::string output;
    output.reserve(value.size());
    for (const char character : value) {
        if (character == '\\')
            output += "\\\\";
        else if (character == '"')
            output += "\\\"";
        else if (character == '\n')
            output += "\\n";
        else
            output.push_back(character);
    }
    return output;
}

std::uint64_t uptime_seconds(const core::Stats& stats) {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::steady_clock::now() - stats.started_at)
                                          .count());
}

std::string human_duration(std::uint64_t seconds) {
    const std::uint64_t days = seconds / 86'400;
    seconds %= 86'400;
    const std::uint64_t hours = seconds / 3'600;
    seconds %= 3'600;
    const std::uint64_t minutes = seconds / 60;
    seconds %= 60;
    return std::format("{}d {}h {}m {}s", days, hours, minutes, seconds);
}

std::int64_t current_timestamp_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string certificate_expiration_time(std::int64_t timestamp_seconds) {
    const std::chrono::sys_seconds expiration{std::chrono::seconds(timestamp_seconds)};
    return std::format("{:%Y-%m-%d %H:%M:%S} UTC", expiration);
}

std::string metrics_body(const core::ServiceState& state,
                         const routing::RoutingTable& routing) {
    const core::Stats& stats = state.stats;
    const core::StatsSnapshot aggregate = stats.snapshot();
    std::ostringstream output;
    const auto counter = [&output](std::string_view name, std::string_view help,
                                   std::uint64_t value) {
        output << "# HELP " << name << ' ' << help << "\n# TYPE " << name << " counter\n"
               << name << ' ' << value << '\n';
    };
    const auto gauge = [&output](std::string_view name, std::string_view help, std::uint64_t value) {
        output << "# HELP " << name << ' ' << help << "\n# TYPE " << name << " gauge\n"
               << name << ' ' << value << '\n';
    };
    output << "# HELP pool_lb_build_info Build and version information.\n"
              "# TYPE pool_lb_build_info gauge\n"
              "pool_lb_build_info{version=\""
           << core::kVersion << "\"} 1\n";
    gauge("pool_lb_uptime_seconds", "Seconds since the process started.", uptime_seconds(stats));
    gauge("pool_lb_connections_active", "Currently admitted miner connections.",
          stats.active_connections.load(std::memory_order_relaxed));
    gauge("pool_lb_io_workers", "Fixed epoll reactor worker threads.",
          stats.io_workers.load(std::memory_order_relaxed));
    counter("pool_lb_connections_accepted_total", "Miner connections admitted at the edge.",
            aggregate.accepted_connections);
    counter("pool_lb_connections_closed_total", "Admitted miner connections closed.",
            aggregate.closed_connections);
    counter("pool_lb_connections_rejected_protocol_total",
            "Connections rejected for invalid Stratum V1 input.",
            aggregate.rejected_protocol);
    counter("pool_lb_connections_rejected_rate_total",
            "Connections rejected by the per-IP rate limit.",
            aggregate.rejected_rate_limit);
    counter("pool_lb_connections_rejected_ip_limit_total",
            "Connections rejected by the per-IP concurrent limit.",
            aggregate.rejected_ip_limit);
    counter("pool_lb_connections_rejected_global_limit_total",
            "Connections rejected by the global concurrent limit.",
            aggregate.rejected_global_limit);
    counter("pool_lb_connections_rejected_global_rate_total",
            "Connections rejected by the process-wide admission rate limit.",
            aggregate.rejected_global_rate);
    counter("pool_lb_connections_rejected_source_capacity_total",
            "Connections rejected because the bounded source table was full.",
            aggregate.rejected_source_capacity);
    counter("pool_lb_connections_rejected_traffic_rate_total",
            "Connections closed after exceeding ongoing byte or message limits.",
            aggregate.rejected_traffic_rate);
    counter("pool_lb_connections_rejected_queue_limit_total",
            "Connections closed by the process-wide queued-byte limit.",
            aggregate.rejected_queue_limit);
    counter("pool_lb_connections_rejected_tls_total", "Connections rejected during TLS setup.",
            aggregate.rejected_tls);
    output << "# HELP pool_lb_tls_certificate_reloads_total TLS certificate reload attempts by result.\n"
              "# TYPE pool_lb_tls_certificate_reloads_total counter\n"
              "pool_lb_tls_certificate_reloads_total{result=\"success\"} "
           << stats.tls_reload_successes.load(std::memory_order_relaxed)
           << "\npool_lb_tls_certificate_reloads_total{result=\"failure\"} "
           << stats.tls_reload_failures.load(std::memory_order_relaxed) << '\n';
    output << "# HELP pool_lb_tls_certificate_expiry_timestamp_seconds Unix timestamp at which "
              "the active TLS leaf certificate expires.\n"
              "# TYPE pool_lb_tls_certificate_expiry_timestamp_seconds gauge\n";
    const auto certificates = state.tls_certificates.load(std::memory_order_acquire);
    for (const core::TlsCertificateStatus& certificate : *certificates)
        output << "pool_lb_tls_certificate_expiry_timestamp_seconds{listener=\""
               << prometheus_label(certificate.listener_name) << "\"} "
               << certificate.expiry_timestamp_seconds << '\n';
    counter("pool_lb_connections_rejected_no_backend_total",
            "Valid connections rejected because no backend was healthy.",
            aggregate.rejected_no_backend);
    counter("pool_lb_upstream_connect_errors_total", "Failed upstream TCP connection attempts.",
            aggregate.upstream_connect_errors);
    counter("pool_lb_client_bytes_total", "Bytes received from miners before framing validation.",
            aggregate.client_bytes);
    counter("pool_lb_upstream_bytes_total", "Bytes received from pool backends.",
            aggregate.upstream_bytes);
    counter("pool_lb_relay_client_reads_paused_total",
            "Times miner reads were paused because the upstream queue hit its high-water mark.",
            aggregate.client_reads_paused);
    counter("pool_lb_relay_upstream_reads_paused_total",
            "Times pool reads were paused because the miner queue hit its high-water mark.",
            aggregate.upstream_reads_paused);
    gauge("pool_lb_queued_bytes", "Bytes currently queued across both relay directions.",
          stats.queued_bytes.load(std::memory_order_relaxed));
    gauge("pool_lb_queued_bytes_limit", "Current process-wide queued-byte limit.",
          stats.queued_bytes_limit.load(std::memory_order_relaxed));
    gauge("pool_lb_queued_bytes_high_water", "Highest process-wide queued-byte total observed.",
          stats.queued_bytes_high_water.load(std::memory_order_relaxed));
    gauge("pool_lb_tracked_client_sources", "Client IP or IPv6-prefix states currently retained.",
          stats.tracked_clients.load(std::memory_order_relaxed));
    counter("pool_lb_reactor_events_processed_total", "Socket events processed by all reactors.",
            aggregate.events_processed);
    counter("pool_lb_reactor_event_batches_total", "Non-empty epoll batches processed.",
            aggregate.event_batches);
    counter("pool_lb_reactor_batch_processing_nanoseconds_total",
            "Nanoseconds spent processing non-empty epoll batches.",
            aggregate.batch_processing_nanoseconds);
    gauge("pool_lb_reactor_batch_processing_nanoseconds_max",
          "Longest non-empty epoll batch processing time since startup.",
          aggregate.maximum_batch_processing_nanoseconds);
    counter("pool_lb_tls_handshake_attempts_total", "TLS handshakes started.",
            aggregate.tls_handshake_attempts);
    counter("pool_lb_tls_handshake_successes_total", "TLS handshakes completed.",
            aggregate.tls_handshake_successes);
    counter("pool_lb_tls_handshake_nanoseconds_total",
            "Nanoseconds spent in completed TLS handshakes.",
            aggregate.tls_handshake_nanoseconds);

    output << "# HELP pool_lb_protocol_errors_total Invalid miner messages by reason.\n"
              "# TYPE pool_lb_protocol_errors_total counter\n";
    for (std::size_t index = 1; index < aggregate.protocol_errors.size(); ++index) {
        const auto error = static_cast<stratum::ValidationError>(index);
        output << "pool_lb_protocol_errors_total{reason=\"" << stratum::validation_error_name(error)
               << "\"} " << aggregate.protocol_errors[index] << '\n';
    }
    output << "# HELP pool_lb_worker_connections_active Active sessions by reactor worker.\n"
              "# TYPE pool_lb_worker_connections_active gauge\n"
              "# HELP pool_lb_worker_events_processed_total Socket events by reactor worker.\n"
              "# TYPE pool_lb_worker_events_processed_total counter\n"
              "# HELP pool_lb_worker_batch_processing_nanoseconds_max Longest epoll batch by reactor worker.\n"
              "# TYPE pool_lb_worker_batch_processing_nanoseconds_max gauge\n";
    for (std::size_t worker_index = 0; worker_index < stats.worker_count(); ++worker_index) {
        const core::WorkerStats& worker = stats.worker(worker_index);
        output << "pool_lb_worker_connections_active{worker=\"" << worker_index << "\"} "
               << worker.active_connections.load(std::memory_order_relaxed) << '\n';
        output << "pool_lb_worker_events_processed_total{worker=\"" << worker_index << "\"} "
               << worker.events_processed.load(std::memory_order_relaxed) << '\n';
        output << "pool_lb_worker_batch_processing_nanoseconds_max{worker=\"" << worker_index
               << "\"} "
               << worker.maximum_batch_processing_nanoseconds.load(std::memory_order_relaxed)
               << '\n';
    }
    output << "# HELP pool_lb_backend_up Backend health (1 = up, 0 = down).\n"
              "# TYPE pool_lb_backend_up gauge\n"
              "# HELP pool_lb_backend_connections_active Active sessions pinned to a backend.\n"
              "# TYPE pool_lb_backend_connections_active gauge\n"
              "# HELP pool_lb_backend_connection_attempts_total Backend connection attempts.\n"
              "# TYPE pool_lb_backend_connection_attempts_total counter\n"
              "# HELP pool_lb_backend_connection_errors_total Backend connection failures.\n"
              "# TYPE pool_lb_backend_connection_errors_total counter\n";
    for (const routing::PoolState& pool : routing.pools)
        for (const auto& backend : pool.backends) {
            const std::string pool_label = prometheus_label(pool.name);
            const std::string backend_label = prometheus_label(backend->name);
            std::string labels = "{pool=\"";
            labels += pool_label;
            labels += "\",backend=\"";
            labels += backend_label;
            labels += "\"}";
            output << "pool_lb_backend_up" << labels << ' '
                   << (backend->healthy.load(std::memory_order_relaxed) ? 1 : 0) << '\n';
            output << "pool_lb_backend_connections_active" << labels << ' '
                   << backend->active_connections.load(std::memory_order_relaxed) << '\n';
            output << "pool_lb_backend_connection_attempts_total" << labels << ' '
                   << backend->connection_attempts.load(std::memory_order_relaxed) << '\n';
            output << "pool_lb_backend_connection_errors_total" << labels << ' '
                   << backend->connection_errors.load(std::memory_order_relaxed) << '\n';
        }
    return output.str();
}

std::string status_body(const core::ServiceState& state, const routing::RoutingTable& routing) {
    const bool routable = routing::has_routable_backend(routing);
    const core::StatsSnapshot aggregate = state.stats.snapshot();
    const auto certificates = state.tls_certificates.load(std::memory_order_acquire);
    const std::int64_t now = current_timestamp_seconds();
    const std::int64_t warning_seconds =
        std::chrono::duration_cast<std::chrono::seconds>(kCertificateExpiryWarning).count();
    const bool certificate_expired =
        std::ranges::any_of(*certificates, [now](const core::TlsCertificateStatus& certificate) {
            return certificate.expiry_timestamp_seconds <= now;
        });
    const bool certificate_expiring = std::ranges::any_of(
        *certificates, [now, warning_seconds](const core::TlsCertificateStatus& certificate) {
            return certificate.expiry_timestamp_seconds - now <= warning_seconds;
        });
    std::string_view state_class = "ok";
    std::string_view state_text = "READY";
    if (!routable) {
        state_class = "bad";
        state_text = "NO ROUTABLE BACKENDS";
    } else if (certificate_expired) {
        state_class = "bad";
        state_text = "TLS CERTIFICATE EXPIRED";
    } else if (certificate_expiring) {
        state_class = "warn";
        state_text = "TLS CERTIFICATE EXPIRING";
    }

    std::ostringstream rows;
    for (const core::TlsCertificateStatus& certificate : *certificates) {
        const bool expired = certificate.expiry_timestamp_seconds <= now;
        const bool expiring = certificate.expiry_timestamp_seconds - now <= warning_seconds;
        const std::int64_t distance = expired ? now - certificate.expiry_timestamp_seconds
                                              : certificate.expiry_timestamp_seconds - now;
        rows << "<tr><td>" << html_escape("TLS " + certificate.listener_name + " certificate")
             << "</td><td class=\"" << (expired ? "bad" : expiring ? "warn" : "ok") << "\">"
             << (expired ? "expired " : "expires ")
             << certificate_expiration_time(certificate.expiry_timestamp_seconds) << " ("
             << human_duration(static_cast<std::uint64_t>(distance))
             << (expired ? " ago" : " remaining") << ")</td></tr>";
    }
    for (const routing::PoolState& pool : routing.pools)
        for (const auto& backend : pool.backends) {
            const bool up = backend->healthy.load(std::memory_order_relaxed);
            rows << "<tr><td>" << html_escape(pool.name + "/" + backend->name) << "</td><td class=\""
                 << (up ? "ok" : "bad") << "\">" << (up ? "up" : "down") << " - "
                 << backend->active_connections.load(std::memory_order_relaxed) << " sessions</td></tr>";
        }
    return std::format(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<link rel=\"icon\" href=\"data:,\"><meta http-equiv=\"refresh\" content=\"5\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>erikslund-pool-lb - {}</title><style>"
        "body{{font-family:system-ui,sans-serif;margin:2rem auto;max-width:46rem;color:#222}}"
        "h1{{font-size:1.4rem;margin-bottom:.2rem}}small{{color:#888;font-weight:400}}"
        "table{{border-collapse:collapse;width:100%;margin-top:1rem}}"
        "td{{padding:.3rem .8rem;border-bottom:1px solid #e5e5e5;vertical-align:top}}"
        "td:first-child{{color:#777;width:14rem}}.ok{{color:#0a7d28}}.bad{{color:#c0392b}}"
        ".warn{{color:#b8860b}}a{{color:#2563eb;text-decoration:none}}</style></head><body>"
        "<h1>erikslund-pool-lb <small>v{} | pid {}</small></h1>"
        "<p class=\"{}\"><strong>{}</strong></p><table>"
        "<tr><td>uptime</td><td>{}</td></tr><tr><td>active pool</td><td>{}</td></tr>"
        "<tr><td>active sessions</td><td>{}</td></tr>"
        "<tr><td>I/O workers</td><td>{}</td></tr>"
        "<tr><td>queued bytes</td><td>{} / {} (high water {})</td></tr>"
        "<tr><td>tracked sources</td><td>{}</td></tr>"
        "<tr><td>maximum reactor batch</td><td>{:.3f} ms</td></tr>{}</table>"
        "<p><a href=\"/\">/</a> | <a href=\"/metrics\">/metrics</a> | "
        "<a href=\"/healthz\">/healthz</a></p></body></html>",
        state_text, core::kVersion, ::getpid(), state_class, state_text,
        human_duration(uptime_seconds(state.stats)), html_escape(routing.active_pool),
        state.stats.active_connections.load(std::memory_order_relaxed),
        state.stats.io_workers.load(std::memory_order_relaxed),
        state.stats.queued_bytes.load(std::memory_order_relaxed),
        state.stats.queued_bytes_limit.load(std::memory_order_relaxed),
        state.stats.queued_bytes_high_water.load(std::memory_order_relaxed),
        state.stats.tracked_clients.load(std::memory_order_relaxed),
        static_cast<double>(aggregate.maximum_batch_processing_nanoseconds) /
            kNanosecondsPerMillisecond,
        rows.str());
}

core::log::Level log_level(http::LogLevel level) {
    switch (level) {
    case http::LogLevel::Debug:
        return core::log::Level::Debug;
    case http::LogLevel::Info:
        return core::log::Level::Info;
    case http::LogLevel::Warning:
        return core::log::Level::Warning;
    case http::LogLevel::Error:
        return core::log::Level::Error;
    }
    return core::log::Level::Info;
}

http::Router make_router(core::ServiceState& state) {
    http::Router router;
    router.get("/", [&state](const http::Request&) {
        const auto runtime = state.runtime.load(std::memory_order_acquire);
        return http::Response::html(status_body(state, *runtime->routing));
    });
    router.get("/status", [&state](const http::Request&) {
        const auto runtime = state.runtime.load(std::memory_order_acquire);
        return http::Response::html(status_body(state, *runtime->routing));
    });
    router.get("/metrics", [&state](const http::Request&) {
        const auto runtime = state.runtime.load(std::memory_order_acquire);
        return http::Response::prometheus(metrics_body(state, *runtime->routing));
    });
    const auto health = [&state](const http::Request&) {
        const auto runtime = state.runtime.load(std::memory_order_acquire);
        const bool healthy = routing::has_routable_backend(*runtime->routing);
        return http::Response::text(healthy ? "ok\n" : "degraded\n",
                                    healthy ? http::Status::Ok
                                            : http::Status::ServiceUnavailable);
    };
    router.get("/health", health);
    router.get("/healthz", health);
    router.get("/favicon.ico",
               [](const http::Request&) { return http::Response::empty(http::Status::NoContent); });
    router.fallback([](const http::Request&) {
        return http::Response::text("not found\n", http::Status::NotFound);
    });
    return router;
}

http::ServerOptions make_options(const core::Config& config) {
    const net::Endpoint endpoint = net::parse_endpoint(config.api_address);

    http::Listener listener;
    listener.bind_address = endpoint.host;
    listener.port = endpoint.port;

    http::ServerOptions options;
    options.listeners.push_back(std::move(listener));
    options.worker_threads = kHttpWorkers;
    options.limits.max_request_line_bytes = kMaximumRequestBytes;
    options.limits.max_header_block_bytes = kMaximumRequestBytes;
    options.limits.max_target_bytes = kMaximumRequestBytes;
    options.limits.max_body_bytes = 0;
    options.max_connections = kMaximumConnections;
    options.header_timeout = kRequestTimeout;
    options.body_timeout = kRequestTimeout;
    options.write_timeout = kRequestTimeout;
    options.request_deadline = kRequestTimeout;
    options.listen_backlog = kListenBacklog;
    options.reuse_port = false;
    options.server_header.clear();
    options.log = [](http::LogLevel level, std::string_view message) {
        const core::log::Level mapped_level = log_level(level);
        if (mapped_level >= core::log::level())
            core::log::write(mapped_level, message);
    };
    return options;
}

} // namespace

HttpServer::HttpServer(const core::Config& config, core::ServiceState& state)
    : server_(make_router(state), make_options(config)) {
    server_.start();
}

void HttpServer::run(const std::stop_token& stop_token) {
    server_.run(stop_token);
}

} // namespace erikslund::api
