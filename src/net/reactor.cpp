#include "net/reactor.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <sys/epoll.h>
#include <sys/socket.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "core/errors.hpp"
#include "core/logging.hpp"
#include "net/pending_buffer.hpp"
#include "net/proxy_protocol.hpp"
#include "net/socket.hpp"
#include "net/timer_wheel.hpp"
#include "net/unique_fd.hpp"
#include "routing/router.hpp"
#include "stratum/validator.hpp"

namespace erikslund::net {

namespace {

constexpr int kListenBacklog = 65'535;
constexpr int kMaximumEvents = 1'024;
constexpr int kEpollWaitMilliseconds = 250;
constexpr std::size_t kIoChunkBytes = 16'384;
constexpr std::size_t kMaximumBytesPerReadyEvent = 65'536;
constexpr std::size_t kMaximumAcceptsPerReadyEvent = 128;
constexpr auto kAcceptResourceBackoff = std::chrono::milliseconds(250);
constexpr std::uint64_t kEventKindMask = 0x3;
// Each read-side mark sits at half the level above it: pause at half the ceiling, resume at half
// the pause mark.
constexpr std::size_t kQueueMarkDivisor = 2;
static_assert(kIoChunkBytes >= SSL3_RT_MAX_PLAIN_LENGTH,
              "the read chunk must hold a whole TLS record so decrypted plaintext cannot strand");
constexpr auto kRelayStallTimeout = std::chrono::seconds(60);

enum class EventKind : std::uint64_t {
    Client = 0,
    Upstream = 1,
    Listener = 2,
};

enum class SessionStage : std::uint8_t {
    TlsHandshake,
    FirstMessage,
    UpstreamConnect,
    Relay,
};

enum class IoStatus : std::uint8_t {
    Data,
    RetryRead,
    RetryWrite,
    Closed,
    Error,
};

enum class TlsOperation : std::uint8_t {
    None,
    Handshake,
    Read,
    Write,
};

enum class IoDirection : std::uint8_t {
    Read,
    Write,
};

struct IoResult {
    IoStatus status;
    std::size_t size = 0;
};

struct ListenerState {
    UniqueFd socket;
    bool tls_enabled = false;
    bool registered = true;
    SteadyClock::time_point resume_at{};
};

std::size_t compatible_source_count(const std::vector<SocketAddress>& sources,
                                    int family) {
    return static_cast<std::size_t>(
        std::ranges::count_if(sources, [family](const SocketAddress& source) {
            return source.family == family;
        }));
}

const SocketAddress* select_compatible_source(const std::vector<SocketAddress>& sources,
                                              int family, std::uint64_t sequence) {
    const std::size_t count = compatible_source_count(sources, family);
    if (count == 0)
        return nullptr;
    std::size_t selected = static_cast<std::size_t>(sequence % count);
    for (const SocketAddress& source : sources) {
        if (source.family != family)
            continue;
        if (selected == 0)
            return &source;
        --selected;
    }
    return nullptr;
}

struct Session {
    std::uint64_t id = 0;
    UniqueFd client;
    UniqueFd upstream;
    Ssl ssl;
    std::shared_ptr<const core::RuntimeSnapshot> runtime;
    std::shared_ptr<routing::BackendState> backend;
    ProxyV2Header proxy_header;
    RateLimiter::Lease admission;
    std::string line_buffer;
    PendingBuffer to_upstream;
    PendingBuffer to_client;
    SessionStage stage = SessionStage::FirstMessage;
    SteadyClock::time_point deadline{};
    SteadyClock::time_point upstream_overall_deadline{};
    SteadyClock::time_point last_activity{};
    SteadyClock::time_point stall_deadline{};
    std::uint32_t client_events = EPOLLIN | EPOLLRDHUP;
    std::uint32_t upstream_events = 0;
    std::uint64_t timeout_generation = 0;
    std::uint64_t upstream_source_sequence = 0;
    std::size_t current_backend_address = 0;
    std::size_t next_backend_address = 0;
    std::size_t backend_addresses_remaining = 0;
    std::size_t current_address_sources_remaining = 0;
    std::size_t connect_candidates_remaining = 0;
    double message_tokens = 0.0;
    double byte_tokens = 0.0;
    SteadyClock::time_point traffic_updated_at{};
    SteadyClock::time_point tls_handshake_started_at{};
    stratum::ProtocolState protocol_state;
    bool backend_counted = false;
    bool client_read_closed = false;
    bool upstream_read_closed = false;
    bool queue_limit_exceeded = false;
    bool client_read_paused = false;
    bool upstream_read_paused = false;
    TlsOperation tls_operation = TlsOperation::None;
    IoDirection tls_direction = IoDirection::Read;
    std::size_t client_write_retry_bytes = 0;
};

std::size_t queue_pause_bytes(const core::LimitsConfig& limits) {
    const std::size_t headroom = limits.max_line_bytes + kIoChunkBytes;
    if (limits.max_buffer_bytes <= headroom)
        return limits.max_buffer_bytes;
    return std::min(limits.max_buffer_bytes / kQueueMarkDivisor,
                    limits.max_buffer_bytes - headroom);
}

std::size_t queue_resume_bytes(const core::LimitsConfig& limits) {
    return queue_pause_bytes(limits) / kQueueMarkDivisor;
}

bool consume_session_traffic(Session& session, std::size_t bytes, std::size_t messages,
                             SteadyClock::time_point now) {
    const core::LimitsConfig& limits = session.runtime->config->limits;
    if (session.traffic_updated_at == SteadyClock::time_point{}) {
        session.message_tokens = static_cast<double>(limits.message_burst_per_connection);
        session.byte_tokens = static_cast<double>(limits.byte_burst_per_connection);
    } else {
        const double elapsed =
            std::chrono::duration<double>(now - session.traffic_updated_at).count();
        session.message_tokens =
            std::min(static_cast<double>(limits.message_burst_per_connection),
                     session.message_tokens +
                         elapsed * limits.messages_per_second_per_connection);
        session.byte_tokens =
            std::min(static_cast<double>(limits.byte_burst_per_connection),
                     session.byte_tokens + elapsed * limits.bytes_per_second_per_connection);
    }
    session.traffic_updated_at = now;
    if (session.message_tokens < static_cast<double>(messages) ||
        session.byte_tokens < static_cast<double>(bytes))
        return false;
    session.message_tokens -= static_cast<double>(messages);
    session.byte_tokens -= static_cast<double>(bytes);
    return true;
}

std::uint64_t event_token(std::uint64_t id, EventKind kind) {
    return (id << 2) | static_cast<std::uint64_t>(kind);
}

std::uint64_t event_id(std::uint64_t token) {
    return token >> 2;
}

EventKind event_kind(std::uint64_t token) {
    return static_cast<EventKind>(token & kEventKindMask);
}

IoResult read_client(Session& session, char* output, std::size_t capacity) {
    if (session.ssl) {
        ERR_clear_error();
        errno = 0;
        const int result = SSL_read(session.ssl.get(), output, static_cast<int>(capacity));
        if (result > 0) {
            session.tls_operation = TlsOperation::None;
            return {IoStatus::Data, static_cast<std::size_t>(result)};
        }
        const int system_error = errno;
        const int error = SSL_get_error(session.ssl.get(), result);
        if (error == SSL_ERROR_WANT_READ) {
            // Waiting for the next application record is the ordinary full-duplex idle state.
            session.tls_operation = TlsOperation::None;
            return {IoStatus::RetryRead};
        }
        if (error == SSL_ERROR_WANT_WRITE) {
            session.tls_operation = TlsOperation::Read;
            session.tls_direction = IoDirection::Write;
            return {IoStatus::RetryWrite};
        }
        if (error == SSL_ERROR_ZERO_RETURN)
            return {IoStatus::Closed};
        // A process-directed reload signal can interrupt the reactor's underlying TLS syscall.
        if (error == SSL_ERROR_SYSCALL && system_error == EINTR) {
            if (session.tls_operation != TlsOperation::Read) {
                session.tls_operation = TlsOperation::Read;
                session.tls_direction = IoDirection::Read;
            }
            return session.tls_direction == IoDirection::Read
                       ? IoResult{IoStatus::RetryRead}
                       : IoResult{IoStatus::RetryWrite};
        }
        return {IoStatus::Error};
    }
    const ssize_t result = ::recv(session.client.get(), output, capacity, 0);
    if (result > 0)
        return {IoStatus::Data, static_cast<std::size_t>(result)};
    if (result == 0)
        return {IoStatus::Closed};
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return {IoStatus::RetryRead};
    return {IoStatus::Error};
}

IoResult write_client(Session& session) {
    if (session.to_client.empty())
        return {IoStatus::Data};
    if (session.ssl) {
        const std::size_t write_size = session.client_write_retry_bytes > 0
                                           ? session.client_write_retry_bytes
                                           : std::min(session.to_client.size(),
                                                      kMaximumBytesPerReadyEvent);
        ERR_clear_error();
        errno = 0;
        const int result = SSL_write(session.ssl.get(), session.to_client.data(),
                                     static_cast<int>(write_size));
        if (result > 0) {
            session.to_client.consume(static_cast<std::size_t>(result));
            session.tls_operation = TlsOperation::None;
            session.client_write_retry_bytes = 0;
            return {IoStatus::Data, static_cast<std::size_t>(result)};
        }
        const int system_error = errno;
        const int error = SSL_get_error(session.ssl.get(), result);
        if (error == SSL_ERROR_WANT_READ) {
            session.tls_operation = TlsOperation::Write;
            session.tls_direction = IoDirection::Read;
            session.client_write_retry_bytes = write_size;
            return {IoStatus::RetryRead};
        }
        if (error == SSL_ERROR_WANT_WRITE) {
            session.tls_operation = TlsOperation::Write;
            session.tls_direction = IoDirection::Write;
            session.client_write_retry_bytes = write_size;
            return {IoStatus::RetryWrite};
        }
        if (error == SSL_ERROR_SYSCALL && system_error == EINTR) {
            if (session.tls_operation != TlsOperation::Write) {
                session.tls_operation = TlsOperation::Write;
                session.tls_direction = IoDirection::Write;
            }
            session.client_write_retry_bytes = write_size;
            return session.tls_direction == IoDirection::Read
                       ? IoResult{IoStatus::RetryRead}
                       : IoResult{IoStatus::RetryWrite};
        }
        return {IoStatus::Error};
    }
    const ssize_t result = ::send(session.client.get(), session.to_client.data(),
                                  std::min(session.to_client.size(),
                                           kMaximumBytesPerReadyEvent),
                                  MSG_NOSIGNAL);
    if (result > 0) {
        session.to_client.consume(static_cast<std::size_t>(result));
        return {IoStatus::Data, static_cast<std::size_t>(result)};
    }
    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return {IoStatus::RetryWrite};
    return {IoStatus::Error};
}

IoResult write_upstream(Session& session) {
    if (session.to_upstream.empty())
        return {IoStatus::Data};
    const ssize_t result = ::send(session.upstream.get(), session.to_upstream.data(),
                                  std::min(session.to_upstream.size(),
                                           kMaximumBytesPerReadyEvent),
                                  MSG_NOSIGNAL);
    if (result > 0) {
        session.to_upstream.consume(static_cast<std::size_t>(result));
        return {IoStatus::Data, static_cast<std::size_t>(result)};
    }
    if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return {IoStatus::RetryWrite};
    return {IoStatus::Error};
}

bool io_direction_ready(IoDirection direction, std::uint32_t events) {
    const std::uint32_t required =
        direction == IoDirection::Read ? EPOLLIN : EPOLLOUT;
    return (events & required) != 0;
}

bool is_accept_resource_error(int error) {
    return error == EMFILE || error == ENFILE || error == ENOBUFS || error == ENOMEM;
}

} // namespace

class Reactor::Impl {
public:
    Impl(const std::vector<ReactorListener>& listeners, TlsContextStore& tls_contexts,
         core::ServiceState& state, RateLimiter& rate_limiter,
         core::WorkerStats& worker_stats, std::size_t expected_sessions)
        : tls_contexts_(tls_contexts), state_(state), rate_limiter_(rate_limiter),
          worker_stats_(worker_stats), epoll_(::epoll_create1(EPOLL_CLOEXEC)),
          timer_wheel_(SteadyClock::now(), expected_sessions) {
        if (!epoll_)
            throw core::IoError(std::string("epoll_create1: ") + std::strerror(errno));
        sessions_.reserve(expected_sessions);
        listener_states_.reserve(listeners.size());
        for (const ReactorListener& listener : listeners) {
            const std::size_t listener_index = listener_states_.size();
            ListenerState runtime{
                .socket = create_listener(listener.socket_address, kListenBacklog, true),
                .tls_enabled = static_cast<bool>(tls_contexts_.context_for(listener_index)),
            };
            add_fd(runtime.socket.get(), EPOLLIN,
                   event_token(listener_index, EventKind::Listener));
            listener_states_.push_back(std::move(runtime));
        }
    }

    void run(const std::stop_token& stop_token) {
        try {
            dispatch_events(stop_token);
        } catch (...) {
            shutdown();
            throw;
        }
        shutdown();
    }

private:
    void dispatch_events(const std::stop_token& stop_token) {
        std::array<epoll_event, kMaximumEvents> events{};
        std::array<char, kIoChunkBytes> input{};
        while (!stop_token.stop_requested()) {
            const auto wait_started_at = SteadyClock::now();
            rearm_listeners(wait_started_at);
            const int ready = ::epoll_wait(epoll_.get(), events.data(), events.size(),
                                           epoll_wait_timeout(wait_started_at));
            if (ready < 0 && errno != EINTR)
                throw core::IoError(std::string("epoll_wait: ") + std::strerror(errno));
            const auto batch_started_at = SteadyClock::now();
            for (int event_index = 0; event_index < std::max(ready, 0); ++event_index) {
                const std::uint64_t token = events[event_index].data.u64;
                const EventKind kind = event_kind(token);
                if (kind == EventKind::Listener) {
                    accept_ready(static_cast<std::size_t>(event_id(token)));
                    continue;
                }
                const std::uint64_t id = event_id(token);
                const auto iterator = sessions_.find(id);
                if (iterator == sessions_.end())
                    continue;
                bool keep = kind == EventKind::Client
                                ? client_ready(iterator->second, events[event_index].events, input)
                                : upstream_ready(iterator->second, events[event_index].events, input);
                if (keep)
                    keep = update_interests(iterator->second);
                if (!keep)
                    close_session(id);
            }
            if (ready > 0)
                worker_stats_.record_event_batch(
                    static_cast<std::size_t>(ready),
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        SteadyClock::now() - batch_started_at));
            expire_timeouts(SteadyClock::now());
        }
    }

    // A stopping worker must drop its listeners. The kernel keeps completing handshakes onto a
    // bound SO_REUSEPORT socket even when no thread accepts from it, so a listener left behind
    // would silently swallow this worker's share of every new connection.
    void shutdown() {
        for (ListenerState& listener : listener_states_) {
            if (!listener.socket)
                continue;
            if (listener.registered)
                ::epoll_ctl(epoll_.get(), EPOLL_CTL_DEL, listener.socket.get(), nullptr);
            listener.registered = false;
            listener.socket.reset();
        }
        while (!sessions_.empty())
            close_session(sessions_.begin()->first);
    }

    void add_fd(int file_descriptor, std::uint32_t events, std::uint64_t token) const {
        if (try_add_fd(file_descriptor, events, token))
            return;
        throw core::IoError(std::string("epoll_ctl(ADD): ") + std::strerror(errno));
    }

    bool try_add_fd(int file_descriptor, std::uint32_t events, std::uint64_t token) const {
        epoll_event event{.events = events, .data = {.u64 = token}};
        return ::epoll_ctl(epoll_.get(), EPOLL_CTL_ADD, file_descriptor, &event) == 0;
    }

    bool modify_fd(int file_descriptor, std::uint32_t events, std::uint64_t token) const {
        epoll_event event{.events = events, .data = {.u64 = token}};
        return ::epoll_ctl(epoll_.get(), EPOLL_CTL_MOD, file_descriptor, &event) == 0;
    }

    int epoll_wait_timeout(SteadyClock::time_point now) const {
        auto timeout = std::chrono::milliseconds(kEpollWaitMilliseconds);
        for (const ListenerState& listener : listener_states_) {
            if (listener.registered)
                continue;
            if (listener.resume_at <= now)
                return 0;
            timeout = std::min(
                timeout,
                std::chrono::ceil<std::chrono::milliseconds>(listener.resume_at - now));
        }
        return static_cast<int>(timeout.count());
    }

    void pause_listener(std::size_t listener_index) {
        ListenerState& listener = listener_states_[listener_index];
        if (listener.registered &&
            ::epoll_ctl(epoll_.get(), EPOLL_CTL_DEL, listener.socket.get(), nullptr) < 0 &&
            errno != ENOENT)
            throw core::IoError(std::string("epoll_ctl(DEL listener): ") +
                                std::strerror(errno));
        listener.registered = false;
        listener.resume_at = SteadyClock::now() + kAcceptResourceBackoff;
    }

    void rearm_listeners(SteadyClock::time_point now) {
        for (std::size_t listener_index = 0; listener_index < listener_states_.size();
             ++listener_index) {
            ListenerState& listener = listener_states_[listener_index];
            if (listener.registered || listener.resume_at > now)
                continue;
            if (try_add_fd(listener.socket.get(), EPOLLIN,
                           event_token(listener_index, EventKind::Listener))) {
                listener.registered = true;
                continue;
            }
            if (is_accept_resource_error(errno)) {
                listener.resume_at = now + kAcceptResourceBackoff;
                continue;
            }
            throw core::IoError(std::string("epoll_ctl(ADD listener): ") +
                                std::strerror(errno));
        }
    }

    bool reserve_queued_bytes(std::size_t bytes) {
        if (state_.stats.try_reserve_queued_bytes(bytes))
            return true;
        worker_stats_.rejected_queue_limit.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    bool append_queued(PendingBuffer& buffer, std::string_view bytes) {
        if (!reserve_queued_bytes(bytes.size()))
            return false;
        try {
            buffer.append(bytes);
        } catch (...) {
            state_.stats.release_queued_bytes(bytes.size());
            throw;
        }
        return true;
    }

    bool prepend_queued(PendingBuffer& buffer, std::string_view bytes) {
        if (!reserve_queued_bytes(bytes.size()))
            return false;
        try {
            buffer.prepend(bytes);
        } catch (...) {
            state_.stats.release_queued_bytes(bytes.size());
            throw;
        }
        return true;
    }

    bool append_line_bytes(Session& session, std::string_view bytes) {
        if (!reserve_queued_bytes(bytes.size()))
            return false;
        try {
            session.line_buffer.append(bytes);
        } catch (...) {
            state_.stats.release_queued_bytes(bytes.size());
            throw;
        }
        return true;
    }

    void release_active_slot() noexcept {
        state_.stats.active_connections.fetch_sub(1, std::memory_order_relaxed);
        worker_stats_.active_connections.fetch_sub(1, std::memory_order_relaxed);
    }

    void accept_ready(std::size_t listener_index) {
        if (listener_index >= listener_states_.size())
            return;
        ListenerState& listener = listener_states_[listener_index];
        if (!listener.registered)
            return;
        const auto runtime = state_.runtime.load(std::memory_order_acquire);
        const auto& config = runtime->config;
        std::size_t attempts_this_event = 0;
        while (attempts_this_event < kMaximumAcceptsPerReadyEvent) {
            ++attempts_this_event;
            sockaddr_storage peer_address{};
            socklen_t peer_length = sizeof(peer_address);
            UniqueFd client(::accept4(listener.socket.get(),
                                      reinterpret_cast<sockaddr*>(&peer_address), &peer_length,
                                      SOCK_CLOEXEC | SOCK_NONBLOCK));
            if (!client) {
                if (errno == EINTR)
                    continue;
                if (is_accept_resource_error(errno)) {
                    pause_listener(listener_index);
                    return;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return;
                return;
            }
            configure_stream_socket(client.get());
            const std::uint64_t prior_active =
                state_.stats.active_connections.fetch_add(1, std::memory_order_relaxed);
            if (prior_active >= config->limits.max_connections) {
                state_.stats.active_connections.fetch_sub(1, std::memory_order_relaxed);
                worker_stats_.rejected_global_limit.fetch_add(1,
                                                               std::memory_order_relaxed);
                continue;
            }
            worker_stats_.active_connections.fetch_add(1, std::memory_order_relaxed);
            sockaddr_storage local_address{};
            socklen_t local_length = sizeof(local_address);
            if (::getsockname(client.get(), reinterpret_cast<sockaddr*>(&local_address),
                              &local_length) < 0) {
                release_active_slot();
                continue;
            }
            const ClientKey admission_key =
                client_rate_limit_key(peer_address, config->limits.ipv6_prefix_bits);
            RateLimiter::Admission admission =
                rate_limiter_.acquire(admission_key, config->limits);
            state_.stats.tracked_clients.store(rate_limiter_.tracked_clients(),
                                               std::memory_order_relaxed);
            if (admission.result != AdmissionResult::Accepted) {
                if (admission.result == AdmissionResult::ConcurrentLimit)
                    worker_stats_.rejected_ip_limit.fetch_add(1,
                                                               std::memory_order_relaxed);
                else if (admission.result == AdmissionResult::GlobalRateLimit)
                    worker_stats_.rejected_global_rate.fetch_add(1,
                                                                 std::memory_order_relaxed);
                else if (admission.result == AdmissionResult::SourceCapacity)
                    worker_stats_.rejected_source_capacity.fetch_add(
                        1, std::memory_order_relaxed);
                else
                    worker_stats_.rejected_rate_limit.fetch_add(1,
                                                                 std::memory_order_relaxed);
                release_active_slot();
                continue;
            }

            Session session;
            session.id = next_session_id_++;
            session.client = std::move(client);
            session.runtime = runtime;
            session.proxy_header = make_proxy_v2_header(peer_address, local_address);
            session.admission = std::move(admission.lease);
            session.last_activity = SteadyClock::now();
            if (listener.tls_enabled) {
                worker_stats_.tls_handshake_attempts.fetch_add(1,
                                                               std::memory_order_relaxed);
                session.tls_handshake_started_at = session.last_activity;
                const SslContext tls_context = tls_contexts_.context_for(listener_index);
                if (!tls_context) {
                    worker_stats_.rejected_tls.fetch_add(1, std::memory_order_relaxed);
                    release_admission(session);
                    continue;
                }
                session.ssl = create_server_stream(*tls_context, session.client.get());
                if (!session.ssl) {
                    worker_stats_.rejected_tls.fetch_add(1, std::memory_order_relaxed);
                    release_admission(session);
                    continue;
                }
                session.stage = SessionStage::TlsHandshake;
                session.deadline = session.last_activity +
                                   std::chrono::seconds(
                                       config->limits.tls_handshake_timeout_seconds);
            } else {
                session.stage = SessionStage::FirstMessage;
                session.deadline = session.last_activity +
                                   std::chrono::seconds(
                                       config->limits.first_message_timeout_seconds);
            }
            const std::uint64_t id = session.id;
            if (!try_add_fd(session.client.get(), EPOLLIN | EPOLLRDHUP,
                            event_token(id, EventKind::Client))) {
                release_admission(session);
                continue;
            }
            const auto [iterator, inserted] = sessions_.emplace(id, std::move(session));
            if (!inserted)
                throw core::IoError("duplicate reactor session identifier");
            Session& stored = iterator->second;
            schedule_timeout(stored);
            worker_stats_.accepted_connections.fetch_add(1, std::memory_order_relaxed);
            if (stored.stage == SessionStage::TlsHandshake) {
                if (!drive_tls_handshake(stored) || !update_interests(stored))
                    close_session(id);
            }
        }
    }

    bool client_ready(Session& session, std::uint32_t events,
                      std::array<char, kIoChunkBytes>& input) {
        if (session.stage == SessionStage::TlsHandshake)
            return drive_tls_handshake(session);
        const bool connection_error = (events & EPOLLERR) != 0;
        const bool full_hangup = (events & EPOLLHUP) != 0;
        if (session.tls_operation == TlsOperation::Write) {
            if (!io_direction_ready(session.tls_direction, events))
                return !connection_error && !full_hangup;
            if (!flush_client(session))
                return false;
            if (session.upstream_read_closed && session.to_client.empty())
                return false;
            // Complete only the exact pending SSL_write in this event. If bytes remain,
            // EPOLLOUT will schedule another fairness-bounded write.
            return !connection_error && !full_hangup;
        }
        bool attempted_read = false;
        bool read_budget_exhausted = false;
        if (session.tls_operation == TlsOperation::Read) {
            if (!io_direction_ready(session.tls_direction, events))
                return !connection_error && !full_hangup;
            attempted_read = true;
            if (!read_from_client(session, input, read_budget_exhausted))
                return false;
        }
        if (!attempted_read && session.tls_operation == TlsOperation::None &&
            !session.client_read_closed && !session.client_read_paused &&
            (events & (EPOLLIN | EPOLLHUP | EPOLLRDHUP)) != 0) {
            if (!read_from_client(session, input, read_budget_exhausted))
                return false;
        }
        if (session.stage == SessionStage::Relay && !session.to_upstream.empty()) {
            const IoResult result = write_upstream(session);
            if (result.status == IoStatus::Error || result.status == IoStatus::Closed)
                return false;
            if (result.status == IoStatus::Data && result.size > 0) {
                state_.stats.release_queued_bytes(result.size);
                session.last_activity = SteadyClock::now();
            }
        }
        if ((events & EPOLLOUT) != 0 && session.tls_operation == TlsOperation::None &&
            !session.to_client.empty() &&
            !flush_client(session))
            return false;
        if (session.upstream_read_closed && session.to_client.empty())
            return false;
        if (connection_error && !read_budget_exhausted)
            return false;
        if (full_hangup && (session.client_read_closed || session.client_read_paused))
            return false;
        if (session.client_read_closed && session.stage == SessionStage::FirstMessage)
            return false;
        return true;
    }

    bool upstream_ready(Session& session, std::uint32_t events,
                        std::array<char, kIoChunkBytes>& input) {
        if (session.stage == SessionStage::UpstreamConnect) {
            if (!finish_upstream_connect(session)) {
                if (session.queue_limit_exceeded)
                    return false;
                record_upstream_error(session);
                discard_upstream(session);
                return SteadyClock::now() < session.upstream_overall_deadline &&
                       start_next_upstream_connect(session);
            }
        }
        std::size_t bytes_this_event = 0;
        if (!session.upstream_read_paused && (events & (EPOLLIN | EPOLLHUP | EPOLLRDHUP)) != 0) {
            while (true) {
                const ssize_t received =
                    ::recv(session.upstream.get(), input.data(), input.size(), 0);
                if (received == 0) {
                    session.upstream_read_closed = true;
                    break;
                }
                if (received < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                        break;
                    return false;
                }
                const std::size_t size = static_cast<std::size_t>(received);
                worker_stats_.upstream_bytes.fetch_add(size, std::memory_order_relaxed);
                if (!append_queued(session.to_client, {input.data(), size}))
                    return false;
                bytes_this_event += size;
                if (session.to_client.size() > session.runtime->config->limits.max_buffer_bytes)
                    return false;
                if (session.to_client.size() >
                    queue_pause_bytes(session.runtime->config->limits))
                    break;
                if (bytes_this_event >= kMaximumBytesPerReadyEvent)
                    break;
            }
            if (bytes_this_event > 0)
                session.last_activity = SteadyClock::now();
        }
        if (session.tls_operation == TlsOperation::None &&
            !session.to_client.empty() && !flush_client(session))
            return false;
        if ((events & EPOLLOUT) != 0 && !session.upstream_read_closed &&
            !session.to_upstream.empty()) {
            const IoResult result = write_upstream(session);
            if (result.status == IoStatus::Error || result.status == IoStatus::Closed)
                return false;
            if (result.status == IoStatus::Data && result.size > 0) {
                state_.stats.release_queued_bytes(result.size);
                session.last_activity = SteadyClock::now();
            }
        }
        if ((events & EPOLLERR) != 0 && bytes_this_event < kMaximumBytesPerReadyEvent)
            return false;
        if (session.upstream_read_paused && (events & EPOLLHUP) != 0)
            session.upstream_read_closed = true;
        if (session.upstream_read_closed) {
            discard_upstream(session);
            return !session.to_client.empty();
        }
        return true;
    }

    bool drive_tls_handshake(Session& session) {
        ERR_clear_error();
        errno = 0;
        const int result = SSL_accept(session.ssl.get());
        if (result == 1) {
            const auto now = SteadyClock::now();
            session.stage = SessionStage::FirstMessage;
            session.tls_operation = TlsOperation::None;
            session.deadline = now +
                               std::chrono::seconds(
                                   session.runtime->config->limits.first_message_timeout_seconds);
            worker_stats_.tls_handshake_successes.fetch_add(1,
                                                            std::memory_order_relaxed);
            const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                now - session.tls_handshake_started_at);
            worker_stats_.tls_handshake_nanoseconds.fetch_add(
                static_cast<std::uint64_t>(elapsed.count()), std::memory_order_relaxed);
            schedule_timeout(session);
            return true;
        }
        const int system_error = errno;
        const int error = SSL_get_error(session.ssl.get(), result);
        if (error == SSL_ERROR_WANT_READ) {
            session.tls_operation = TlsOperation::Handshake;
            session.tls_direction = IoDirection::Read;
            return true;
        }
        if (error == SSL_ERROR_WANT_WRITE) {
            session.tls_operation = TlsOperation::Handshake;
            session.tls_direction = IoDirection::Write;
            return true;
        }
        if (error == SSL_ERROR_SYSCALL && system_error == EINTR) {
            if (session.tls_operation != TlsOperation::Handshake) {
                session.tls_operation = TlsOperation::Handshake;
                session.tls_direction = IoDirection::Read;
            }
            return true;
        }
        worker_stats_.rejected_tls.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    bool flush_client(Session& session) {
        const IoResult result = write_client(session);
        if (result.status == IoStatus::Error || result.status == IoStatus::Closed)
            return false;
        if (result.status == IoStatus::Data && result.size > 0) {
            state_.stats.release_queued_bytes(result.size);
            session.last_activity = SteadyClock::now();
        }
        return true;
    }

    bool read_from_client(Session& session, std::array<char, kIoChunkBytes>& input,
                          bool& budget_exhausted) {
        budget_exhausted = false;
        std::size_t bytes_this_event = 0;
        std::size_t messages_this_event = 0;
        while (true) {
            const IoResult result = read_client(session, input.data(), input.size());
            if (result.status == IoStatus::RetryRead)
                return true;
            if (result.status == IoStatus::RetryWrite)
                return true;
            if (result.status == IoStatus::Closed) {
                session.client_read_closed = true;
                session.tls_operation = TlsOperation::None;
                if (!session.line_buffer.empty()) {
                    worker_stats_.record_protocol_error(stratum::ValidationError::InvalidShape);
                    return false;
                }
                return true;
            }
            if (result.status != IoStatus::Data)
                return false;
            worker_stats_.client_bytes.fetch_add(result.size, std::memory_order_relaxed);
            const auto now = SteadyClock::now();
            session.last_activity = now;
            const std::size_t messages = static_cast<std::size_t>(
                std::count(input.begin(), input.begin() + static_cast<std::ptrdiff_t>(result.size),
                           '\n'));
            if (messages > session.runtime->config->limits.max_messages_per_ready_event ||
                messages_this_event >
                    session.runtime->config->limits.max_messages_per_ready_event - messages ||
                !consume_session_traffic(session, result.size, messages, now) ||
                !rate_limiter_.consume_traffic(session.admission, result.size, messages,
                                               session.runtime->config->limits, now)) {
                worker_stats_.rejected_traffic_rate.fetch_add(1,
                                                              std::memory_order_relaxed);
                return false;
            }
            messages_this_event += messages;
            if (!process_client_bytes(session, {input.data(), result.size}))
                return false;
            if (session.to_upstream.size() > queue_pause_bytes(session.runtime->config->limits))
                return true;
            bytes_this_event += result.size;
            if (bytes_this_event >= kMaximumBytesPerReadyEvent) {
                budget_exhausted = true;
                return true;
            }
        }
    }

    bool process_client_bytes(Session& session, std::string_view bytes) {
        if (!append_line_bytes(session, bytes))
            return false;
        std::size_t consumed = 0;
        while (true) {
            const std::size_t newline = session.line_buffer.find('\n', consumed);
            if (newline == std::string::npos)
                break;
            const std::size_t line_size = newline - consumed;
            if (line_size > session.runtime->config->limits.max_line_bytes) {
                worker_stats_.record_protocol_error(stratum::ValidationError::InvalidShape);
                return false;
            }
            const std::string_view line(session.line_buffer.data() + consumed, line_size);
            const auto validation = stratum::validate_request(
                line, session.protocol_state, session.runtime->config->protocol);
            if (!validation) {
                worker_stats_.record_protocol_error(validation.error);
                return false;
            }
            consumed = newline + 1;
            const bool initial_message = !session.protocol_state.received_message;
            stratum::record_request(session.protocol_state, validation.method);
            if (initial_message) {
                if (!begin_upstream_connect(session))
                    return false;
            }
        }
        if (consumed > 0) {
            const std::size_t maximum_buffer =
                session.runtime->config->limits.max_buffer_bytes;
            if (consumed > maximum_buffer ||
                session.to_upstream.size() > maximum_buffer - consumed) {
                worker_stats_.record_protocol_error(stratum::ValidationError::InvalidShape);
                return false;
            }
            // These bytes already hold a process-wide queue reservation in line_buffer. Move
            // their logical ownership in one append instead of reserving and releasing once per
            // line, which also avoids transient false rejections near the global queue limit.
            session.to_upstream.append(
                std::string_view(session.line_buffer.data(), consumed));
            session.line_buffer.erase(0, consumed);
            release_oversized_string(session.line_buffer);
        }
        if (session.line_buffer.size() > session.runtime->config->limits.max_line_bytes ||
            session.to_upstream.size() > session.runtime->config->limits.max_buffer_bytes) {
            worker_stats_.record_protocol_error(stratum::ValidationError::InvalidShape);
            return false;
        }
        return true;
    }

    bool begin_upstream_connect(Session& session) {
        const auto& routing = session.runtime->routing;
        const std::uint64_t selection = route_sequence_++;
        session.backend = routing::select_backend(*routing, selection);
        if (!session.backend) {
            worker_stats_.rejected_no_backend.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        const std::size_t address_count = session.backend->socket_addresses.size();
        if (address_count == 0) {
            worker_stats_.rejected_no_backend.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        session.stage = SessionStage::UpstreamConnect;
        session.upstream_overall_deadline =
            SteadyClock::now() +
            std::chrono::milliseconds(
                session.runtime->config->limits.upstream_connect_timeout_milliseconds);
        session.next_backend_address = selection % address_count;
        session.backend_addresses_remaining = address_count;
        const auto& sources = routing->upstream_source_addresses;
        if (sources.empty()) {
            session.connect_candidates_remaining = address_count;
        } else {
            session.upstream_source_sequence = upstream_source_sequence_++;
            session.connect_candidates_remaining = 0;
            for (const SocketAddress& address : session.backend->socket_addresses)
                session.connect_candidates_remaining +=
                    compatible_source_count(sources, address.family);
        }
        session.current_address_sources_remaining = 0;
        if (session.connect_candidates_remaining == 0) {
            worker_stats_.rejected_no_backend.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        return start_next_upstream_connect(session);
    }

    bool start_next_upstream_connect(Session& session) {
        const std::size_t address_count = session.backend->socket_addresses.size();
        if (address_count == 0)
            return false;
        const auto& sources = session.runtime->routing->upstream_source_addresses;
        while (session.connect_candidates_remaining > 0 &&
               SteadyClock::now() < session.upstream_overall_deadline) {
            while (session.current_address_sources_remaining == 0 &&
                   session.backend_addresses_remaining > 0) {
                session.current_backend_address = session.next_backend_address;
                session.next_backend_address =
                    (session.next_backend_address + 1) % address_count;
                --session.backend_addresses_remaining;
                const int family =
                    session.backend->socket_addresses[session.current_backend_address].family;
                session.current_address_sources_remaining =
                    sources.empty() ? 1 : compatible_source_count(sources, family);
            }
            if (session.current_address_sources_remaining == 0)
                return false;
            const auto& address =
                session.backend->socket_addresses[session.current_backend_address];
            const SocketAddress* source = nullptr;
            if (!sources.empty()) {
                source = select_compatible_source(sources, address.family,
                                                  session.upstream_source_sequence++);
                if (source == nullptr)
                    return false;
            }
            --session.current_address_sources_remaining;
            --session.connect_candidates_remaining;
            session.backend->connection_attempts.fetch_add(1, std::memory_order_relaxed);
            ConnectStart started = start_connect(address, source);
            if (!started.socket) {
                record_upstream_error(session);
                continue;
            }
            session.upstream = std::move(started.socket);
            if (!try_add_fd(session.upstream.get(), EPOLLOUT | EPOLLRDHUP,
                            event_token(session.id, EventKind::Upstream))) {
                record_upstream_error(session);
                session.upstream.reset();
                continue;
            }
            session.upstream_events = EPOLLOUT | EPOLLRDHUP;
            schedule_connect_attempt_timeout(session);
            if (!started.connected)
                return true;
            if (finish_upstream_connect(session))
                return true;
            if (session.queue_limit_exceeded)
                return false;
            record_upstream_error(session);
            discard_upstream(session);
        }
        return false;
    }

    void schedule_connect_attempt_timeout(Session& session) {
        const auto now = SteadyClock::now();
        const auto remaining = session.upstream_overall_deadline - now;
        const auto attempts =
            static_cast<std::int64_t>(session.connect_candidates_remaining + 1);
        const auto slice = remaining / attempts;
        session.deadline = std::min(now + slice, session.upstream_overall_deadline);
        schedule_timeout(session);
    }

    bool finish_upstream_connect(Session& session) {
        int socket_error = 0;
        socklen_t error_length = sizeof(socket_error);
        if (::getsockopt(session.upstream.get(), SOL_SOCKET, SO_ERROR, &socket_error,
                         &error_length) < 0 ||
            socket_error != 0)
            return false;
        session.stage = SessionStage::Relay;
        schedule_timeout(session);
        session.backend->active_connections.fetch_add(1, std::memory_order_relaxed);
        session.backend_counted = true;
        if (session.backend->send_proxy_v2 &&
            !prepend_queued(session.to_upstream, session.proxy_header.view())) {
            session.queue_limit_exceeded = true;
            return false;
        }
        return true;
    }

    void discard_upstream(Session& session) const {
        if (session.upstream)
            ::epoll_ctl(epoll_.get(), EPOLL_CTL_DEL, session.upstream.get(), nullptr);
        session.upstream.reset();
        session.upstream_events = 0;
        session.upstream_read_paused = false;
    }

    void record_upstream_error(Session& session) const {
        if (session.backend)
            session.backend->connection_errors.fetch_add(1, std::memory_order_relaxed);
        worker_stats_.upstream_connect_errors.fetch_add(1, std::memory_order_relaxed);
    }

    void refresh_read_pause(Session& session) {
        const core::LimitsConfig& limits = session.runtime->config->limits;
        const std::size_t pause_mark = queue_pause_bytes(limits);
        const std::size_t resume_mark = queue_resume_bytes(limits);
        const bool tls_buffer_drained = !session.ssl || SSL_pending(session.ssl.get()) == 0;
        const bool client_paused =
            tls_buffer_drained &&
            (session.client_read_paused ? session.to_upstream.size() > resume_mark
                                        : session.to_upstream.size() > pause_mark);
        const bool upstream_paused =
            session.upstream_read_paused ? session.to_client.size() > resume_mark
                                         : session.to_client.size() > pause_mark;
        const bool was_paused = session.client_read_paused || session.upstream_read_paused;
        if (client_paused && !session.client_read_paused)
            worker_stats_.client_reads_paused.fetch_add(1, std::memory_order_relaxed);
        if (upstream_paused && !session.upstream_read_paused)
            worker_stats_.upstream_reads_paused.fetch_add(1, std::memory_order_relaxed);
        session.client_read_paused = client_paused;
        session.upstream_read_paused = upstream_paused;
        const bool is_paused = client_paused || upstream_paused;
        if (is_paused == was_paused)
            return;
        if (is_paused)
            session.stall_deadline = SteadyClock::now() + kRelayStallTimeout;
        if (session.stage == SessionStage::Relay)
            schedule_timeout(session);
    }

    bool update_interests(Session& session) {
        refresh_read_pause(session);
        const bool suppress_client_reads =
            session.client_read_closed ||
            (session.client_read_paused && session.tls_operation == TlsOperation::None);
        std::uint32_t client_events =
            suppress_client_reads ? 0U : static_cast<std::uint32_t>(EPOLLRDHUP);
        if (!session.client_read_closed && session.tls_operation != TlsOperation::None) {
            client_events |= session.tls_direction == IoDirection::Read
                                 ? static_cast<std::uint32_t>(EPOLLIN)
                                 : static_cast<std::uint32_t>(EPOLLOUT);
        } else {
            if (!suppress_client_reads)
                client_events |= EPOLLIN;
            if (!session.to_client.empty())
                client_events |= EPOLLOUT;
        }
        if (client_events != session.client_events) {
            if (!modify_fd(session.client.get(), client_events,
                           event_token(session.id, EventKind::Client)))
                return false;
            session.client_events = client_events;
        }
        if (session.upstream) {
            std::uint32_t upstream_events =
                session.upstream_read_paused ? 0U : static_cast<std::uint32_t>(EPOLLRDHUP);
            if (session.stage == SessionStage::UpstreamConnect) {
                upstream_events |= EPOLLOUT;
            } else {
                if (!session.upstream_read_paused)
                    upstream_events |= EPOLLIN;
                if (!session.to_upstream.empty())
                    upstream_events |= EPOLLOUT;
            }
            if (upstream_events != session.upstream_events) {
                if (!modify_fd(session.upstream.get(), upstream_events,
                               event_token(session.id, EventKind::Upstream)))
                    return false;
                session.upstream_events = upstream_events;
            }
        }
        return true;
    }

    SteadyClock::time_point timeout_deadline(const Session& session) const {
        if (session.stage != SessionStage::Relay)
            return session.deadline;
        if (session.client_read_paused || session.upstream_read_paused)
            return session.stall_deadline;
        return session.last_activity +
               std::chrono::seconds(session.runtime->config->limits.idle_timeout_seconds);
    }

    void schedule_timeout(Session& session) {
        ++session.timeout_generation;
        timer_wheel_.schedule(session.id, session.timeout_generation,
                              timeout_deadline(session));
    }

    void expire_timeouts(SteadyClock::time_point now) {
        for (const TimerExpiry expiry : timer_wheel_.advance(now)) {
            const auto iterator = sessions_.find(expiry.session_id);
            if (iterator == sessions_.end() ||
                iterator->second.timeout_generation != expiry.generation)
                continue;
            Session& session = iterator->second;
            const SteadyClock::time_point deadline = timeout_deadline(session);
            if (now < deadline) {
                timer_wheel_.schedule(expiry.session_id, expiry.generation, deadline);
            } else if (session.stage == SessionStage::UpstreamConnect) {
                record_upstream_error(session);
                discard_upstream(session);
                if (now >= session.upstream_overall_deadline ||
                    !start_next_upstream_connect(session))
                    close_session(expiry.session_id);
            } else {
                if (session.stage == SessionStage::TlsHandshake)
                    worker_stats_.rejected_tls.fetch_add(1, std::memory_order_relaxed);
                close_session(expiry.session_id);
            }
        }
    }

    void release_admission(Session& session) {
        session.admission.reset();
        release_active_slot();
    }

    void close_session(std::uint64_t id) {
        const auto iterator = sessions_.find(id);
        if (iterator == sessions_.end())
            return;
        Session& session = iterator->second;
        ::epoll_ctl(epoll_.get(), EPOLL_CTL_DEL, session.client.get(), nullptr);
        if (session.upstream)
            ::epoll_ctl(epoll_.get(), EPOLL_CTL_DEL, session.upstream.get(), nullptr);
        if (session.backend_counted)
            session.backend->active_connections.fetch_sub(1, std::memory_order_relaxed);
        timer_wheel_.cancel(id);
        const std::size_t queued_bytes = session.line_buffer.size() +
                                         session.to_upstream.size() +
                                         session.to_client.size();
        state_.stats.release_queued_bytes(queued_bytes);
        release_admission(session);
        worker_stats_.closed_connections.fetch_add(1, std::memory_order_relaxed);
        sessions_.erase(iterator);
    }

    TlsContextStore& tls_contexts_;
    core::ServiceState& state_;
    RateLimiter& rate_limiter_;
    core::WorkerStats& worker_stats_;
    UniqueFd epoll_;
    std::vector<ListenerState> listener_states_;
    std::unordered_map<std::uint64_t, Session> sessions_;
    TimerWheel timer_wheel_;
    std::uint64_t next_session_id_ = 1;
    std::uint64_t route_sequence_ = 0;
    std::uint64_t upstream_source_sequence_ = 0;
};

Reactor::Reactor(const std::vector<ReactorListener>& listeners, TlsContextStore& tls_contexts,
                  core::ServiceState& state, RateLimiter& rate_limiter,
                  core::WorkerStats& worker_stats, std::size_t expected_sessions)
    : impl_(std::make_unique<Impl>(listeners, tls_contexts, state, rate_limiter,
                                   worker_stats, expected_sessions)) {}

Reactor::~Reactor() = default;

void Reactor::run(const std::stop_token& stop_token) {
    impl_->run(stop_token);
}

} // namespace erikslund::net
