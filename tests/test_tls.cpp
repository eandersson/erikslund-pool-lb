#include <doctest/doctest.h>

#include <atomic>

#include <sys/socket.h>

#include <openssl/ssl.h>

#include "net/tls.hpp"
#include "net/unique_fd.hpp"

namespace {

void record_context_free([[maybe_unused]] void* parent,
                         void* pointer,
                         [[maybe_unused]] CRYPTO_EX_DATA* data,
                         [[maybe_unused]] int index,
                         [[maybe_unused]] long argument,
                         [[maybe_unused]] void* argument_pointer) {
    if (pointer == nullptr)
        return;
    auto& free_count = *static_cast<std::atomic<int>*>(pointer);
    free_count.fetch_add(1, std::memory_order_relaxed);
}

} // namespace

TEST_CASE("TLS context publication preserves contexts held by established sessions") {
    erikslund::net::SslContext first(
        SSL_CTX_new(TLS_server_method()), erikslund::net::SslContextDeleter{});
    erikslund::net::SslContext second(
        SSL_CTX_new(TLS_server_method()), erikslund::net::SslContextDeleter{});
    REQUIRE(first);
    REQUIRE(second);

    erikslund::net::TlsContextStore store;
    store.publish({first, {}});
    const erikslund::net::SslContext established_session = store.context_for(0);
    CHECK(established_session.get() == first.get());
    CHECK_FALSE(store.context_for(1));

    store.publish({second, {}});
    CHECK(store.context_for(0).get() == second.get());
    CHECK(established_session.get() == first.get());
}

TEST_CASE("TLS streams retain their context after its shared owner is released") {
    std::atomic<int> context_free_count{0};
    const int lifetime_index = SSL_CTX_get_ex_new_index(
        0, nullptr, nullptr, nullptr, record_context_free);
    REQUIRE(lifetime_index >= 0);
    erikslund::net::SslContext context(
        SSL_CTX_new(TLS_server_method()), erikslund::net::SslContextDeleter{});
    REQUIRE(context);
    REQUIRE(SSL_CTX_set_ex_data(context.get(), lifetime_index, &context_free_count) == 1);
    SSL_CTX* const raw_context = context.get();

    int descriptors[2] = {-1, -1};
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, descriptors) == 0);
    erikslund::net::UniqueFd server_socket(descriptors[0]);
    erikslund::net::UniqueFd peer_socket(descriptors[1]);
    REQUIRE(peer_socket);
    auto stream = erikslund::net::create_server_stream(*context, server_socket.get());
    REQUIRE(stream);

    context.reset();
    CHECK(SSL_get_SSL_CTX(stream.get()) == raw_context);
    CHECK(context_free_count.load(std::memory_order_relaxed) == 0);

    stream.reset();
    CHECK(context_free_count.load(std::memory_order_relaxed) == 1);
}
