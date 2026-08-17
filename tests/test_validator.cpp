#include <doctest/doctest.h>

#include <string>

#include "core/config.hpp"
#include "stratum/validator.hpp"

using erikslund::core::ProtocolConfig;
using erikslund::stratum::ProtocolState;
using erikslund::stratum::RequestMethod;
using erikslund::stratum::ValidationError;
using erikslund::stratum::record_request;
using erikslund::stratum::validate_request;

TEST_CASE("validator accepts normal SV1 client methods") {
    const ProtocolConfig config;
    ProtocolState state;
    CHECK(validate_request(R"({"id":1,"method":"mining.subscribe","params":["cgminer/4.12"]})",
                           state, config));
    record_request(state, "mining.subscribe");
    CHECK(validate_request(R"({"id":2,"method":"mining.authorize","params":["bc1q.worker","x"]})",
                           state, config));
    record_request(state, "mining.authorize");
    CHECK(validate_request(
        R"({"id":3,"method":"mining.submit","params":["worker","job","00","time","nonce"]})",
        state, config));
}

TEST_CASE("validator accepts firmware replies to server-initiated requests") {
    const ProtocolConfig config;
    ProtocolState state;
    REQUIRE(validate_request(R"({"id":1,"method":"mining.subscribe","params":[]})", state, config));
    record_request(state, "mining.subscribe");

    // What cgminer-derived firmware sends back when a pool asks client.get_version.
    const auto version_reply =
        validate_request(R"({"id":7,"result":"cgminer/4.11.1","error":null})", state, config);
    CHECK(version_reply);
    CHECK(version_reply.method == RequestMethod::Response);
    CHECK(validate_request(R"({"id":8,"result":true,"error":null})", state, config));
    CHECK(validate_request(R"({"id":9,"result":null,"error":[20,"Other/Unknown",null]})", state,
                           config));

    // A reply must not advance the handshake it is not part of.
    record_request(state, RequestMethod::Response);
    CHECK_FALSE(state.authorized);
}

TEST_CASE("validator still refuses a response as the opening line") {
    const ProtocolConfig config;
    const ProtocolState state;
    CHECK(validate_request(R"({"id":7,"result":"cgminer/4.11.1","error":null})", state, config)
              .error == ValidationError::InvalidShape);
    // Still not a request, and still missing the result/error a response must carry.
    ProtocolState started;
    record_request(started, "mining.subscribe");
    CHECK(validate_request(R"({"id":7})", started, config).error ==
          ValidationError::InvalidShape);
    CHECK(validate_request(R"({"result":true,"error":null})", started, config).error ==
          ValidationError::InvalidShape);
    CHECK(validate_request(R"({"id":{},"result":true,"error":null})", started, config).error ==
          ValidationError::InvalidId);
}

TEST_CASE("validator rejects scanning and malformed messages") {
    const ProtocolConfig config;
    const ProtocolState state;
    CHECK(validate_request("GET / HTTP/1.1", state, config).error == ValidationError::InvalidJson);
    CHECK(validate_request(R"({"id":1,"method":"eth_submitLogin","params":[]})", state,
                           config)
              .error == ValidationError::InvalidMethod);
    CHECK(validate_request(R"({"id":1,"method":"eth_submitLogin","params":[]})", state,
                           config)
              .rejected_method == "eth_submitLogin");
    CHECK(validate_request(R"({"id":1,"method":"mining.subscribe","params":"wrong"})", state,
                           config)
              .error == ValidationError::InvalidParams);
    CHECK(validate_request(R"({"id":{},"method":"mining.subscribe","params":[]})", state,
                           config)
              .error == ValidationError::InvalidId);
}

TEST_CASE("validator rejects submit as a first message") {
    const ProtocolConfig config;
    const ProtocolState state;
    CHECK(validate_request(R"({"id":1,"method":"mining.submit","params":[]})", state, config)
              .error == ValidationError::InvalidInitialMethod);
}

TEST_CASE("validator enforces nesting without counting braces inside strings") {
    ProtocolConfig config;
    const ProtocolState state;
    config.max_json_depth = 4;
    CHECK(validate_request(
        R"({"id":1,"method":"mining.authorize","params":["{{{{{{{{{{","x"]})", state,
        config));
    CHECK(validate_request(
              R"({"id":1,"method":"mining.configure","params":[[[[["x"]]]]]})", state,
              config)
              .error == ValidationError::TooDeep);
}

TEST_CASE("unknown mining extensions require an explicit compatibility switch") {
    ProtocolConfig strict;
    const ProtocolState state{.received_message = true};
    CHECK(validate_request(R"({"id":1,"method":"mining.vendor_extension","params":[]})", state,
                           strict)
              .error == ValidationError::InvalidMethod);
    strict.allow_unknown_mining_methods = true;
    CHECK(validate_request(R"({"id":1,"method":"mining.vendor_extension","params":[]})", state,
                           strict));
}

TEST_CASE("configured extensions are allowed without enabling every mining method") {
    ProtocolConfig config;
    config.additional_allowed_methods = {"mining.vendor_extension"};
    const ProtocolState established{.received_message = true};
    CHECK(validate_request(
        R"({"id":1,"method":"mining.vendor_extension","params":["worker",42,true,null]})",
        established, config));
    CHECK(validate_request(R"({"id":1,"method":"mining.other","params":[]})", established,
                           config)
              .error == ValidationError::InvalidMethod);
    CHECK(validate_request(
              R"({"id":1,"method":"mining.vendor_extension","params":[{"nested":true}]})",
              established, config)
              .error == ValidationError::InvalidParams);
}

TEST_CASE("only explicitly configured extension methods may start a session") {
    ProtocolConfig config;
    config.additional_allowed_methods = {"mining.vendor_handshake",
                                         "mining.vendor_extension"};
    config.additional_initial_methods = {"mining.vendor_handshake"};
    const ProtocolState initial;
    CHECK(validate_request(
        R"({"id":1,"method":"mining.vendor_handshake","params":["miner"]})", initial,
        config));
    CHECK(validate_request(
              R"({"id":1,"method":"mining.vendor_extension","params":[]})", initial,
              config)
              .error == ValidationError::InvalidInitialMethod);
}

TEST_CASE("validator enforces method parameters and conservative request order") {
    const ProtocolConfig config;
    ProtocolState state;
    CHECK(validate_request(R"({"id":1,"method":"mining.subscribe","params":["miner"]})", state,
                           config));
    record_request(state, "mining.subscribe");
    CHECK(validate_request(
              R"({"id":2,"method":"mining.submit","params":["w","j","00","time","nonce"]})",
              state, config)
              .error == ValidationError::InvalidSequence);
    CHECK(validate_request(R"({"id":3,"method":"mining.authorize","params":["worker"]})", state,
                           config)
              .error == ValidationError::InvalidParams);
    CHECK(validate_request(R"({"id":3,"method":"mining.authorize","params":["worker","x"]})",
                           state, config));
    record_request(state, "mining.authorize");
    CHECK(validate_request(
        R"({"id":4,"method":"mining.submit","params":["w","j","00","time","nonce"]})",
        state, config));
}

TEST_CASE("validator bounds extension parameter cardinality") {
    ProtocolConfig config;
    config.allow_unknown_mining_methods = true;
    const ProtocolState state{.received_message = true};
    CHECK(validate_request(
              R"({"id":1,"method":"mining.vendor",)"
              R"("params":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]})",
              state, config)
              .error == ValidationError::InvalidParams);
}

TEST_CASE("validator classifies methods once for protocol state updates") {
    const ProtocolConfig config;
    ProtocolState state;

    const auto subscribe = validate_request(
        R"({"id":1,"method":"mining.subscribe","params":["miner"]})", state, config);
    REQUIRE(subscribe);
    CHECK(subscribe.method == RequestMethod::Subscribe);
    CHECK(subscribe.rejected_method.empty());
    record_request(state, subscribe.method);
    CHECK(state.received_message);
    CHECK(state.subscribed);
    CHECK_FALSE(state.authorized);

    const auto authorize = validate_request(
        R"({"id":2,"method":"mining.authorize","params":["worker","x"]})", state,
        config);
    REQUIRE(authorize);
    CHECK(authorize.method == RequestMethod::Authorize);
    record_request(state, authorize.method);
    CHECK(state.authorized);
}

TEST_CASE("validator decodes escaped built-in and configured method names") {
    ProtocolConfig config;
    config.additional_allowed_methods = {"mining.vendor"};
    config.additional_initial_methods = {"mining.vendor"};
    const ProtocolState initial;

    const auto subscribe = validate_request(
        R"({"id":1,"method":"mining.\u0073ubscribe","params":[]})", initial, config);
    REQUIRE(subscribe);
    CHECK(subscribe.method == RequestMethod::Subscribe);

    const auto extension = validate_request(
        R"({"id":2,"method":"mining.\u0076endor","params":[true,1,"x"]})", initial,
        config);
    REQUIRE(extension);
    CHECK(extension.method == RequestMethod::Extension);
}

TEST_CASE("validator accepts every built-in method with its valid state and parameters") {
    const ProtocolConfig config;
    const ProtocolState initial;
    const ProtocolState established{.received_message = true,
                                    .subscribed = true,
                                    .authorized = true};
    const auto accepted = [&config](std::string_view request, const ProtocolState& state) {
        CHECK(validate_request(request, state, config));
    };

    accepted(R"({"id":1,"method":"mining.authorize","params":["w","x"]})", initial);
    accepted(R"({"id":1,"method":"mining.capabilities","params":[{}]})", established);
    accepted(R"({"id":1,"method":"mining.configure","params":[[],{}]})", initial);
    accepted(R"({"id":1,"method":"mining.extranonce.subscribe","params":[]})", initial);
    accepted(R"({"id":1,"method":"mining.get_transactions","params":["job"]})",
             established);
    accepted(R"({"id":1,"method":"mining.multi_version","params":[1,true,null]})",
             established);
    accepted(R"({"id":1,"method":"mining.resume","params":["session"]})", established);
    accepted(R"({"id":1,"method":"mining.submit","params":["w","j","00","t","n"]})",
             established);
    accepted(R"({"id":1,"method":"mining.subscribe","params":[]})", initial);
    accepted(R"({"id":1,"method":"mining.suggest_difficulty","params":[1.5]})", initial);
    accepted(R"({"id":1,"method":"mining.suggest_target","params":["target"]})",
             established);
    accepted(R"({"id":1,"method":"mining.update_password","params":["w","x"]})",
             established);
}

TEST_CASE("validator measures decoded parameter strings") {
    const ProtocolConfig config;
    const ProtocolState established{.received_message = true};
    const std::string target(128, 'a');
    const std::string accepted =
        R"({"id":1,"method":"mining.suggest_target","params":[")" + target + R"("]})";
    CHECK(validate_request(accepted, established, config));

    std::string escaped;
    escaped.reserve(128 * 6);
    for (int index = 0; index < 128; ++index)
        escaped += R"(\u0061)";
    const std::string escaped_request =
        R"({"id":1,"method":"mining.suggest_target","params":[")" + escaped + R"("]})";
    CHECK(validate_request(escaped_request, established, config));

    escaped += R"(\u0061)";
    const std::string oversized_request =
        R"({"id":1,"method":"mining.suggest_target","params":[")" + escaped + R"("]})";
    CHECK(validate_request(oversized_request, established, config).error ==
          ValidationError::InvalidParams);
}

TEST_CASE("validator preserves precise envelope error categories") {
    const ProtocolConfig config;
    const ProtocolState initial;
    CHECK(validate_request("null", initial, config).error == ValidationError::InvalidShape);
    CHECK(validate_request("[]", initial, config).error == ValidationError::InvalidShape);
    CHECK(validate_request("{", initial, config).error == ValidationError::InvalidJson);
    CHECK(validate_request(R"({"id":1})", initial, config).error ==
          ValidationError::InvalidShape);
    CHECK(validate_request(R"({"method":1,"params":[]})", initial, config).error ==
          ValidationError::InvalidShape);
    CHECK(validate_request(R"({"method":"mining.subscribe","params":{}})", initial,
                           config)
              .error == ValidationError::InvalidParams);
}

TEST_CASE("validator accepts compatible metadata but validates its JSON") {
    const ProtocolConfig config;
    const ProtocolState initial;
    CHECK(validate_request(
        R"({"jsonrpc":"2.0","metadata":{"nested":[1,true,null]},)"
        R"("id":1,"method":"mining.subscribe","params":[]})",
        initial, config));

    const std::string invalid_utf8 =
        std::string{R"({"metadata":")"} + '\xff' +
        R"(","id":1,"method":"mining.subscribe","params":[]})";
    CHECK(validate_request(invalid_utf8, initial, config).error ==
          ValidationError::InvalidJson);
}

TEST_CASE("validator rejects coalesced JSON values but accepts a framed CR suffix") {
    const ProtocolConfig config;
    const ProtocolState initial;
    CHECK(validate_request(
              R"({"id":1,"method":"mining.subscribe","params":[]})"
              R"({"id":2,"method":"mining.subscribe","params":[]})",
              initial, config)
              .error == ValidationError::InvalidJson);
    CHECK(validate_request(
        "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}\r", initial,
        config));
}
