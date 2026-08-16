#pragma once
// OpenSSL server contexts, atomic credential rotation, and per-client TLS streams.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <openssl/ssl.h>

namespace erikslund::net {

struct SslContextDeleter {
    void operator()(SSL_CTX* context) const noexcept;
};

struct SslDeleter {
    void operator()(SSL* ssl) const noexcept;
};

using SslContext = std::shared_ptr<SSL_CTX>;
using Ssl = std::unique_ptr<SSL, SslDeleter>;

class TlsContextStore {
public:
    TlsContextStore() = default;

    TlsContextStore(const TlsContextStore&) = delete;
    TlsContextStore& operator=(const TlsContextStore&) = delete;

    [[nodiscard]] SslContext context_for(std::size_t listener_index) const;
    void publish(std::vector<SslContext> contexts);

private:
    struct ContextSlot {
        std::atomic<SslContext> context;
    };

    std::vector<std::unique_ptr<ContextSlot>> contexts_;
};

SslContext create_server_context(const std::string& certificate_file,
                                 const std::string& private_key_file);
[[nodiscard]] std::int64_t certificate_expiry_timestamp_seconds(const SslContext& context);
Ssl create_server_stream(SSL_CTX& context, int file_descriptor);

} // namespace erikslund::net
