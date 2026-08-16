// Adversarial coverage for the bounded Stratum V1 JSON-RPC validator.
#include <doctest/doctest.h>

#include <array>
#include <string>
#include <string_view>

#include "core/config.hpp"
#include "stratum/validator.hpp"

using erikslund::core::ProtocolConfig;
using erikslund::stratum::ProtocolState;
using erikslund::stratum::ValidationError;
using erikslund::stratum::validate_request;

TEST_CASE("validator rejects non-object, truncated, and cross-protocol input") {
    const ProtocolConfig config;
    const ProtocolState state;
    constexpr std::array<std::string_view, 14> inputs = {
        " ",
        "null",
        "true",
        "42",
        R"("string")",
        "[]",
        R"(["mining.subscribe",1])",
        "{",
        R"({"method":)",
        R"({"method":"mining.subscribe",})",
        "GET / HTTP/1.1\r",
        "SSH-2.0-OpenSSH_9.0",
        "<?xml version=\"1.0\"?>",
        std::string_view{"\x16\x03\x01\x00\x2a", 5},
    };

    for (const std::string_view input : inputs)
        CHECK_FALSE(validate_request(input, state, config));
}

TEST_CASE("validator rejects control bytes and malformed UTF-8 without throwing") {
    const ProtocolConfig config;
    const ProtocolState state;
    const std::array<std::string, 4> inputs = {
        std::string{"\0\x01\x02", 3},
        std::string{"\xff\xfe\xfd", 3},
        std::string{"{\"id\":1,\"method\":\"mining.\xff\",\"params\":[]}"},
        std::string{"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"\x80\"]}"},
    };

    for (const std::string& input : inputs)
        CHECK_FALSE(validate_request(input, state, config));
}

TEST_CASE("validator bounds nesting, identity size, and parameter cardinality") {
    ProtocolConfig config;
    config.max_json_depth = 8;
    const ProtocolState initial;

    std::string deep = R"({"id":1,"method":"mining.configure","params":)";
    deep.append(16, '[');
    deep += '0';
    deep.append(16, ']');
    deep += '}';
    CHECK(validate_request(deep, initial, config).error == ValidationError::TooDeep);

    const std::string oversized_identity(513, 'a');
    const std::string authorize =
        R"({"id":1,"method":"mining.authorize","params":[")" + oversized_identity +
        R"(","x"]})";
    CHECK(validate_request(authorize, initial, config).error == ValidationError::InvalidParams);

    config.allow_unknown_mining_methods = true;
    const ProtocolState established{.received_message = true};
    CHECK(validate_request(
              R"({"id":1,"method":"mining.vendor","params":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]})",
              established, config)
              .error == ValidationError::InvalidParams);
    CHECK(validate_request(
              R"({"id":1,"method":"mining.vendor","params":[{"nested":"object"}]})",
              established, config)
              .error == ValidationError::InvalidParams);
}

TEST_CASE("validator rejects ambiguous ids and method shapes") {
    const ProtocolConfig config;
    const ProtocolState state;
    for (const std::string_view input : {
             R"({"id":1.5,"method":"mining.subscribe","params":[]})",
             R"({"id":true,"method":"mining.subscribe","params":[]})",
             R"({"id":[],"method":"mining.subscribe","params":[]})",
             R"({"id":{},"method":"mining.subscribe","params":[]})",
             R"({"id":1,"method":null,"params":[]})",
             R"({"id":1,"method":["mining.subscribe"],"params":[]})",
         }) {
        CHECK_FALSE(validate_request(input, state, config));
    }
}
