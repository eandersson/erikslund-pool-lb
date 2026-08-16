#include <doctest/doctest.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "core/config.hpp"
#include "core/service_state.hpp"
#include "net/server.hpp"
#include "net/tls.hpp"
#include "net/unique_fd.hpp"
#include "routing/router.hpp"
#include "socket_test_utils.hpp"

using namespace std::chrono_literals;

namespace {

void require_openssl_success(int result, std::string_view operation) {
    if (result != 1)
        throw std::runtime_error("OpenSSL test setup failed: " + std::string(operation));
}

std::string temporary_file_path(std::string_view name) {
    std::string path = "/tmp/erikslund-pool-lb-" + std::string(name) + "-XXXXXX";
    std::vector<char> writable(path.begin(), path.end());
    writable.push_back('\0');
    const int descriptor = ::mkstemp(writable.data());
    if (descriptor < 0)
        throw std::runtime_error("cannot create temporary TLS test file");
    ::close(descriptor);
    return writable.data();
}

class TemporaryTlsCredentials {
public:
    explicit TemporaryTlsCredentials(long serial)
        : certificate_file_(temporary_file_path("certificate")),
          private_key_file_(temporary_file_path("private-key")) {
        using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>;
        using Key = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
        using Certificate = std::unique_ptr<X509, decltype(&::X509_free)>;
        using File = std::unique_ptr<std::FILE, decltype(&::fclose)>;

        KeyContext key_context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
                               ::EVP_PKEY_CTX_free);
        if (!key_context)
            throw std::runtime_error("cannot create TLS test key context");
        require_openssl_success(EVP_PKEY_keygen_init(key_context.get()), "keygen init");
        require_openssl_success(EVP_PKEY_CTX_set_rsa_keygen_bits(key_context.get(), 2'048),
                                "RSA key size");
        EVP_PKEY* raw_key = nullptr;
        require_openssl_success(EVP_PKEY_keygen(key_context.get(), &raw_key), "keygen");
        Key key(raw_key, ::EVP_PKEY_free);

        Certificate certificate(X509_new(), ::X509_free);
        if (!certificate)
            throw std::runtime_error("cannot create TLS test certificate");
        require_openssl_success(X509_set_version(certificate.get(), 2), "certificate version");
        require_openssl_success(
            ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial),
            "certificate serial");
        if (X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) == nullptr ||
            X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3'600) == nullptr)
            throw std::runtime_error("cannot set TLS test certificate validity");
        require_openssl_success(X509_set_pubkey(certificate.get(), key.get()),
                                "certificate public key");
        X509_NAME* subject = X509_get_subject_name(certificate.get());
        constexpr std::string_view kCommonName = "localhost";
        require_openssl_success(
            X509_NAME_add_entry_by_txt(
                subject, "CN", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>(kCommonName.data()),
                static_cast<int>(kCommonName.size()), -1, 0),
            "certificate common name");
        require_openssl_success(X509_set_issuer_name(certificate.get(), subject),
                                "certificate issuer");
        if (X509_sign(certificate.get(), key.get(), EVP_sha256()) <= 0)
            throw std::runtime_error("cannot sign TLS test certificate");

        File certificate_file(std::fopen(certificate_file_.c_str(), "w"), ::fclose);
        File private_key_file(std::fopen(private_key_file_.c_str(), "w"), ::fclose);
        if (!certificate_file || !private_key_file)
            throw std::runtime_error("cannot open temporary TLS test credentials");
        require_openssl_success(PEM_write_X509(certificate_file.get(), certificate.get()),
                                "write certificate");
        require_openssl_success(
            PEM_write_PrivateKey(private_key_file.get(), key.get(), nullptr, nullptr, 0,
                                 nullptr, nullptr),
            "write private key");
    }

    ~TemporaryTlsCredentials() {
        ::unlink(certificate_file_.c_str());
        ::unlink(private_key_file_.c_str());
    }

    TemporaryTlsCredentials(const TemporaryTlsCredentials&) = delete;
    TemporaryTlsCredentials& operator=(const TemporaryTlsCredentials&) = delete;

    [[nodiscard]] const std::string& certificate_file() const noexcept {
        return certificate_file_;
    }

    [[nodiscard]] const std::string& private_key_file() const noexcept {
        return private_key_file_;
    }

private:
    std::string certificate_file_;
    std::string private_key_file_;
};

class PersistentBackend {
public:
    PersistentBackend()
        : listener_(erikslund::test::bind_loopback_listener(true)),
          thread_([this](const std::stop_token& token) { run(token); }) {}

    [[nodiscard]] std::uint16_t port() const noexcept {
        return listener_.port;
    }

private:
    void run(const std::stop_token& token) {
        while (!token.stop_requested()) {
            pollfd descriptor{listener_.socket.get(), POLLIN, 0};
            if (::poll(&descriptor, 1, 100) <= 0)
                continue;
            erikslund::net::UniqueFd client(
                ::accept4(listener_.socket.get(), nullptr, nullptr, SOCK_CLOEXEC));
            if (!client)
                continue;
            int response_id = 1;
            while (!token.stop_requested() &&
                   !erikslund::test::read_line(client.get()).empty()) {
                const std::string response =
                    "{\"id\":" + std::to_string(response_id++) +
                    ",\"result\":true,\"error\":null}\n";
                if (!erikslund::test::send_all(client.get(), response))
                    break;
            }
        }
    }

    erikslund::test::BoundListener listener_;
    std::jthread thread_;
};

erikslund::core::Config tls_config(std::uint16_t listener_port,
                                   std::uint16_t backend_port,
                                   const TemporaryTlsCredentials& credentials) {
    erikslund::core::Config config;
    config.listeners = {{.name = "unit-tls",
                         .address = "127.0.0.1:" + std::to_string(listener_port),
                         .tls = true,
                         .certificate_file = credentials.certificate_file(),
                         .private_key_file = credentials.private_key_file()}};
    config.pools = {{.name = "primary",
                     .backends = {{.name = "backend",
                                   .address = "127.0.0.1:" +
                                              std::to_string(backend_port),
                                   .health_address = {},
                                   .send_proxy_v2 = false}}}};
    config.active_pool = "primary";
    config.io_workers = 1;
    config.limits.max_connections = 16;
    config.limits.max_connections_per_ip = 16;
    config.limits.connections_per_second_per_ip = 1'000.0;
    config.limits.connection_burst_per_ip = 16;
    config.limits.messages_per_second_per_connection = 1'000.0;
    config.limits.message_burst_per_connection = 16;
    config.limits.idle_timeout_seconds = 5;
    return config;
}

struct TlsClient {
    erikslund::net::UniqueFd socket;
    erikslund::net::Ssl stream;
};

TlsClient connect_tls(std::uint16_t port, SSL_CTX& context) {
    TlsClient client{.socket = erikslund::test::connect_loopback(port), .stream = {}};
    REQUIRE(client.socket);
    client.stream.reset(SSL_new(&context));
    REQUIRE(client.stream);
    REQUIRE(SSL_set_fd(client.stream.get(), client.socket.get()) == 1);
    REQUIRE(SSL_connect(client.stream.get()) == 1);
    return client;
}

bool tls_send_all(SSL& stream, std::string_view bytes) {
    while (!bytes.empty()) {
        const int sent = SSL_write(&stream, bytes.data(), static_cast<int>(bytes.size()));
        if (sent <= 0)
            return false;
        bytes.remove_prefix(static_cast<std::size_t>(sent));
    }
    return true;
}

std::string tls_read_line(SSL& stream) {
    std::string line;
    char character = '\0';
    while (SSL_read(&stream, &character, 1) == 1) {
        line.push_back(character);
        if (character == '\n')
            break;
    }
    return line;
}

} // namespace

TEST_CASE("established TLS session survives abrupt peer failure and context rotation") {
    TemporaryTlsCredentials original_credentials(1);
    TemporaryTlsCredentials replacement_credentials(2);
    PersistentBackend backend;
    REQUIRE(backend.port() != 0);
    const std::uint16_t listener_port = erikslund::test::unused_loopback_port();
    REQUIRE(listener_port != 0);

    auto mutable_config = tls_config(listener_port, backend.port(), original_credentials);
    const auto config =
        std::make_shared<const erikslund::core::Config>(std::move(mutable_config));
    erikslund::core::ServiceState state;
    auto routing = erikslund::routing::make_routing_table(*config);
    routing->pools.front().backends.front()->healthy.store(true);
    state.publish(config, routing);

    erikslund::net::SslContext client_context(
        SSL_CTX_new(TLS_client_method()), erikslund::net::SslContextDeleter{});
    REQUIRE(client_context);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);

    erikslund::net::EdgeServer edge(*config, state);
    edge.start();
    auto persistent = connect_tls(listener_port, *client_context);
    constexpr std::string_view subscribe =
        "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\n";
    REQUIRE(tls_send_all(*persistent.stream, subscribe));
    CHECK(tls_read_line(*persistent.stream) ==
          "{\"id\":1,\"result\":true,\"error\":null}\n");

    auto abrupt = connect_tls(listener_port, *client_context);
    abrupt.socket.reset();
    abrupt.stream.reset();
    REQUIRE(erikslund::test::wait_until(
        [&state] { return state.stats.snapshot().closed_connections >= 1; }, 2s));

    auto replacement = tls_config(listener_port, backend.port(), replacement_credentials);
    edge.reload_tls(replacement);
    constexpr std::string_view authorize =
        "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"worker\",\"x\"]}\n";
    REQUIRE(tls_send_all(*persistent.stream, authorize));
    CHECK(tls_read_line(*persistent.stream) ==
          "{\"id\":2,\"result\":true,\"error\":null}\n");

    persistent.stream.reset();
    persistent.socket.reset();
    edge.stop();
}
