#include "net/tls.hpp"

#include <chrono>
#include <ctime>
#include <format>

#include <openssl/err.h>
#include <openssl/x509.h>

#include "core/errors.hpp"

namespace erikslund::net {

SslContext TlsContextStore::context_for(std::size_t listener_index) const {
    if (listener_index >= contexts_.size())
        return {};
    return contexts_[listener_index]->context.load(std::memory_order_acquire);
}

void TlsContextStore::publish(std::vector<SslContext> contexts) {
    if (contexts_.empty()) {
        contexts_.reserve(contexts.size());
        for (std::size_t index = 0; index < contexts.size(); ++index)
            contexts_.push_back(std::make_unique<ContextSlot>());
    } else if (contexts_.size() != contexts.size()) {
        throw core::ConfigError("TLS listener topology changed during context publication");
    }
    for (std::size_t index = 0; index < contexts.size(); ++index)
        contexts_[index]->context.store(std::move(contexts[index]),
                                        std::memory_order_release);
}

void SslContextDeleter::operator()(SSL_CTX* context) const noexcept {
    SSL_CTX_free(context);
}

void SslDeleter::operator()(SSL* ssl) const noexcept {
    SSL_free(ssl);
}

SslContext create_server_context(const std::string& certificate_file,
                                 const std::string& private_key_file) {
    SslContext context(SSL_CTX_new(TLS_server_method()), SslContextDeleter{});
    if (!context)
        throw core::ConfigError("cannot create OpenSSL server context");
    SSL_CTX_set_min_proto_version(context.get(), TLS1_2_VERSION);
    SSL_CTX_set_options(context.get(), SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION |
                                         SSL_OP_CIPHER_SERVER_PREFERENCE);
    // Miner sessions are long lived; short handshake floods must not grow server-side cache state.
    // TLS tickets remain available for stateless session resumption.
    SSL_CTX_set_session_cache_mode(context.get(), SSL_SESS_CACHE_OFF);
    SSL_CTX_set_mode(context.get(), SSL_MODE_ENABLE_PARTIAL_WRITE |
                                        SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                                        SSL_MODE_RELEASE_BUFFERS);
    if (SSL_CTX_use_certificate_chain_file(context.get(), certificate_file.c_str()) != 1)
        throw core::ConfigError("cannot load TLS certificate chain: " + certificate_file);
    if (SSL_CTX_use_PrivateKey_file(context.get(), private_key_file.c_str(), SSL_FILETYPE_PEM) != 1)
        throw core::ConfigError("cannot load TLS private key: " + private_key_file);
    if (SSL_CTX_check_private_key(context.get()) != 1)
        throw core::ConfigError("TLS certificate and private key do not match");
    return context;
}

std::int64_t certificate_expiry_timestamp_seconds(const SslContext& context) {
    const X509* certificate = SSL_CTX_get0_certificate(context.get());
    if (certificate == nullptr)
        throw core::ConfigError("TLS context has no leaf certificate");
    std::tm expiration{};
    if (ASN1_TIME_to_tm(X509_get0_notAfter(certificate), &expiration) != 1)
        throw core::ConfigError("cannot parse TLS certificate expiration");

    const std::chrono::year_month_day date{
        std::chrono::year(expiration.tm_year + 1'900),
        std::chrono::month(static_cast<unsigned int>(expiration.tm_mon + 1)),
        std::chrono::day(static_cast<unsigned int>(expiration.tm_mday))};
    if (!date.ok())
        throw core::ConfigError("TLS certificate has an invalid expiration date");
    const std::chrono::sys_seconds expiration_time =
        std::chrono::sys_days(date) + std::chrono::hours(expiration.tm_hour) +
        std::chrono::minutes(expiration.tm_min) + std::chrono::seconds(expiration.tm_sec);
    return expiration_time.time_since_epoch().count();
}

Ssl create_server_stream(SSL_CTX& context, int file_descriptor) {
    // SSL_new retains the context, so a reloaded context can outlive its published shared owner.
    Ssl ssl(SSL_new(&context));
    if (!ssl)
        return {};
    SSL_set_fd(ssl.get(), file_descriptor);
    SSL_set_accept_state(ssl.get());
    return ssl;
}

} // namespace erikslund::net
