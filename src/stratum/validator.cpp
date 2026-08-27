#include "stratum/validator.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include <glaze/containers/inplace_vector.hpp>
#include <glaze/glaze.hpp>

namespace erikslund::stratum {

namespace {

struct MethodEntry {
    std::string_view name;
    RequestMethod method;
};

constexpr std::array<MethodEntry, 12> kBuiltInMethods = {{
    {"mining.authorize", RequestMethod::Authorize},
    {"mining.capabilities", RequestMethod::Capabilities},
    {"mining.configure", RequestMethod::Configure},
    {"mining.extranonce.subscribe", RequestMethod::ExtranonceSubscribe},
    {"mining.get_transactions", RequestMethod::GetTransactions},
    {"mining.multi_version", RequestMethod::MultiVersion},
    {"mining.resume", RequestMethod::Resume},
    {"mining.submit", RequestMethod::Submit},
    {"mining.subscribe", RequestMethod::Subscribe},
    {"mining.suggest_difficulty", RequestMethod::SuggestDifficulty},
    {"mining.suggest_target", RequestMethod::SuggestTarget},
    {"mining.update_password", RequestMethod::UpdatePassword},
}};

constexpr bool built_in_methods_are_sorted() noexcept {
    for (std::size_t index = 1; index < kBuiltInMethods.size(); ++index)
        if (kBuiltInMethods[index - 1].name >= kBuiltInMethods[index].name)
            return false;
    return true;
}

static_assert(built_in_methods_are_sorted());

constexpr std::size_t kMaximumGenericParams = 16;
constexpr std::size_t kMaximumIdentityBytes = 512;
constexpr std::size_t kMaximumShortStringBytes = 128;
constexpr std::size_t kMaximumConfigureExtensions = 32;
constexpr std::size_t kMaximumConfigureOptions = 64;
constexpr std::size_t kMaximumSubscribeParams = 8;
constexpr std::size_t kMaximumAuthorizeParams = 2;

using RawParams = glz::inplace_vector<glz::raw_json_view, kMaximumGenericParams>;

struct RequestEnvelope {
    std::optional<glz::raw_json_view> id;
    std::optional<glz::raw_json_view> method;
    std::optional<glz::raw_json_view> params;
    std::optional<glz::raw_json_view> result;
    std::optional<glz::raw_json_view> error;

    struct glaze {
        using T = RequestEnvelope;
        static constexpr auto value =
            glz::object("id", &T::id, "method", &T::method, "params", &T::params, "result",
                        &T::result, "error", &T::error);
    };
};

struct EnvelopeReadOptions : glz::opts {
    bool validate_skipped = true;
    bool validate_trailing_whitespace = true;
};

consteval EnvelopeReadOptions envelope_read_options() {
    EnvelopeReadOptions options;
    options.error_on_unknown_keys = false;
    return options;
}

inline constexpr EnvelopeReadOptions kEnvelopeReadOptions = envelope_read_options();

struct DecodedString {
    std::string storage;
    std::string_view value;
};

bool within_depth(std::string_view text, int maximum_depth) {
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (const char character : text) {
        if (in_string) {
            if (escaped)
                escaped = false;
            else if (character == '\\')
                escaped = true;
            else if (character == '"')
                in_string = false;
            continue;
        }
        if (character == '"') {
            in_string = true;
        } else if (character == '{' || character == '[') {
            if (++depth > maximum_depth)
                return false;
        } else if ((character == '}' || character == ']') && depth > 0) {
            --depth;
        }
    }
    return true;
}

std::string_view trim_json_whitespace(std::string_view value) {
    const std::size_t first = value.find_first_not_of(" \t\n\r");
    if (first == std::string_view::npos)
        return {};
    const std::size_t last = value.find_last_not_of(" \t\n\r");
    return value.substr(first, last - first + 1);
}

bool decode_json_string(std::string_view raw, DecodedString& decoded) {
    raw = trim_json_whitespace(raw);
    if (raw.size() < 2 || raw.front() != '"' || raw.back() != '"')
        return false;
    const std::string_view contents = raw.substr(1, raw.size() - 2);
    if (!contents.contains('\\')) {
        decoded.value = contents;
        return true;
    }
    if (glz::read_json(decoded.storage, raw))
        return false;
    decoded.value = decoded.storage;
    return true;
}

RequestMethod built_in_method(std::string_view method) {
    const auto iterator = std::lower_bound(
        kBuiltInMethods.begin(), kBuiltInMethods.end(), method,
        [](const MethodEntry& entry, std::string_view candidate) {
            return entry.name < candidate;
        });
    if (iterator == kBuiltInMethods.end() || iterator->name != method)
        return RequestMethod::Unknown;
    return iterator->method;
}

std::optional<RequestMethod> allowed_method(std::string_view method,
                                            const core::ProtocolConfig& config) {
    const RequestMethod built_in = built_in_method(method);
    if (built_in != RequestMethod::Unknown)
        return built_in;
    if (std::ranges::find(config.additional_allowed_methods, method) !=
        config.additional_allowed_methods.end())
        return RequestMethod::Extension;
    if (config.allow_unknown_mining_methods && method.starts_with("mining.") &&
        method.size() <= core::kMaximumProtocolMethodBytes)
        return RequestMethod::Extension;
    return std::nullopt;
}

bool allowed_initial_method(RequestMethod method, std::string_view method_name,
                            const core::ProtocolConfig& config) {
    switch (method) {
    case RequestMethod::Authorize:
    case RequestMethod::Configure:
    case RequestMethod::ExtranonceSubscribe:
    case RequestMethod::Subscribe:
    case RequestMethod::SuggestDifficulty:
    case RequestMethod::Resume:
        return true;
    case RequestMethod::Extension:
        return std::ranges::find(config.additional_initial_methods, method_name) !=
               config.additional_initial_methods.end();
    default:
        return false;
    }
}

ValidationError valid_id(std::string_view raw) {
    raw = trim_json_whitespace(raw);
    if (raw == "null" || (!raw.empty() && raw.front() == '"'))
        return ValidationError::None;
    if (raw.empty() || (raw.front() != '-' && (raw.front() < '0' || raw.front() > '9')))
        return ValidationError::InvalidId;
    double value = 0.0;
    if (glz::read_json(value, raw))
        return ValidationError::InvalidJson;
    return std::isfinite(value) && value == std::floor(value) ? ValidationError::None
                                                              : ValidationError::InvalidId;
}

ValidationError bounded_string(std::string_view raw, std::size_t maximum,
                               bool require_nonempty = false) {
    DecodedString decoded;
    if (!decode_json_string(raw, decoded))
        return ValidationError::InvalidParams;
    if (decoded.value.size() > maximum || (require_nonempty && decoded.value.empty()))
        return ValidationError::InvalidParams;
    return ValidationError::None;
}

ValidationError strings_only(const RawParams& params,
                             std::size_t minimum, std::size_t maximum,
                             std::size_t maximum_string_bytes) {
    if (params.size() < minimum || params.size() > maximum)
        return ValidationError::InvalidParams;
    for (const glz::raw_json_view& param : params)
        if (const ValidationError error =
                bounded_string(param.str, maximum_string_bytes);
            error != ValidationError::None)
            return error;
    return ValidationError::None;
}

ValidationError primitive_params(const RawParams& params, std::size_t maximum) {
    if (params.size() > maximum)
        return ValidationError::InvalidParams;
    for (const glz::raw_json_view& param : params) {
        const std::string_view raw = trim_json_whitespace(param.str);
        if (raw == "null" || raw == "true" || raw == "false")
            continue;
        if (!raw.empty() && raw.front() == '"') {
            if (const ValidationError error = bounded_string(raw, kMaximumIdentityBytes);
                error != ValidationError::None)
                return error;
            continue;
        }
        if (!raw.empty() && (raw.front() == '-' || (raw.front() >= '0' && raw.front() <= '9'))) {
            double value = 0.0;
            if (glz::read_json(value, raw))
                return ValidationError::InvalidJson;
            continue;
        }
        return ValidationError::InvalidParams;
    }
    return ValidationError::None;
}

ValidationError configure_params(const RawParams& params) {
    if (params.empty())
        return ValidationError::None;
    if (params.size() != 2)
        return ValidationError::InvalidParams;
    glz::generic extensions;
    glz::generic options;
    if (glz::read_json(extensions, params[0].str) ||
        glz::read_json(options, params[1].str))
        return ValidationError::InvalidJson;
    if (!extensions.is_array() || !options.is_object() ||
        extensions.size() > kMaximumConfigureExtensions ||
        options.size() > kMaximumConfigureOptions)
        return ValidationError::InvalidParams;
    return ValidationError::None;
}

ValidationError capabilities_params(const RawParams& params) {
    if (params.empty())
        return ValidationError::None;
    if (params.size() != 1)
        return ValidationError::InvalidParams;
    glz::generic capabilities;
    if (glz::read_json(capabilities, params.front().str))
        return ValidationError::InvalidJson;
    return capabilities.is_object() && capabilities.size() <= kMaximumConfigureOptions
               ? ValidationError::None
               : ValidationError::InvalidParams;
}

ValidationError valid_params(RequestMethod method, const RawParams& params) {
    if (params.size() > kMaximumGenericParams)
        return ValidationError::InvalidParams;
    switch (method) {
    case RequestMethod::Authorize:
        return params.empty() ? ValidationError::InvalidParams
                              : primitive_params(params, kMaximumAuthorizeParams);
    case RequestMethod::UpdatePassword:
        return strings_only(params, 2, 2, kMaximumIdentityBytes);
    case RequestMethod::Submit:
        return strings_only(params, 5, 6, kMaximumIdentityBytes);
    case RequestMethod::Subscribe:
    case RequestMethod::ExtranonceSubscribe:
        return primitive_params(params, kMaximumSubscribeParams);
    case RequestMethod::SuggestTarget:
        return strings_only(params, 1, 1, kMaximumShortStringBytes);
    case RequestMethod::SuggestDifficulty: {
        if (params.size() != 1)
            return ValidationError::InvalidParams;
        const std::string_view raw = trim_json_whitespace(params.front().str);
        if (!raw.empty() && (raw.front() == '-' || (raw.front() >= '0' && raw.front() <= '9'))) {
            double value = 0.0;
            if (glz::read_json(value, raw))
                return ValidationError::InvalidJson;
            return std::isfinite(value) && value > 0.0 ? ValidationError::None
                                                       : ValidationError::InvalidParams;
        }
        return bounded_string(raw, kMaximumShortStringBytes, true);
    }
    case RequestMethod::Configure:
        return configure_params(params);
    case RequestMethod::Capabilities:
        return capabilities_params(params);
    case RequestMethod::GetTransactions:
        return strings_only(params, 1, 1, kMaximumIdentityBytes);
    default:
        return primitive_params(params, kMaximumGenericParams);
    }
}

bool valid_sequence(RequestMethod method, const ProtocolState& state) {
    switch (method) {
    case RequestMethod::Submit:
        return (state.subscribed && state.authorized) || state.resumed;
    case RequestMethod::GetTransactions:
        return state.subscribed;
    case RequestMethod::UpdatePassword:
        return state.authorized;
    default:
        return true;
    }
}

ValidationResult reject(ValidationError error, RequestMethod method = RequestMethod::Unknown,
                        std::string_view method_name = {}) {
    return {
        .error = error,
        .method = method,
        .rejected_method = std::string(method_name),
    };
}

} // namespace

ValidationResult validate_request(std::string_view line, const ProtocolState& state,
                                  const core::ProtocolConfig& config) {
    if (!line.empty() && line.back() == '\r')
        line.remove_suffix(1);
    if (line.empty())
        return reject(ValidationError::Empty);
    if (!within_depth(line, config.max_json_depth))
        return reject(ValidationError::TooDeep);

    const std::string_view trimmed = trim_json_whitespace(line);
    if (trimmed.empty())
        return reject(ValidationError::InvalidJson);
    if (trimmed.front() != '{') {
        glz::generic document;
        if (glz::read_json(document, line))
            return reject(ValidationError::InvalidJson);
        return reject(ValidationError::InvalidShape);
    }

    RequestEnvelope envelope;
    if (glz::read<kEnvelopeReadOptions>(envelope, line))
        return reject(ValidationError::InvalidJson);
    if (!envelope.method) {
        if (!state.received_message)
            return reject(ValidationError::InvalidShape);
        glz::generic document;
        if (glz::read_json(document, line))
            return reject(ValidationError::InvalidJson);
        if (!document.is_object() || !document.contains("id") ||
            (!document.contains("result") && !document.contains("error")))
            return reject(ValidationError::InvalidShape);
        const glz::generic& id = document["id"];
        if (!id.is_null() && !id.is_string() && !id.is_number())
            return reject(ValidationError::InvalidId, RequestMethod::Response);
        return {.error = ValidationError::None,
                .method = RequestMethod::Response,
                .rejected_method = {}};
    }

    DecodedString decoded_method;
    if (!decode_json_string(envelope.method->str, decoded_method)) {
        const std::string_view raw_method = trim_json_whitespace(envelope.method->str);
        return reject(!raw_method.empty() && raw_method.front() == '"'
                          ? ValidationError::InvalidJson
                          : ValidationError::InvalidShape);
    }
    const std::optional<RequestMethod> method = allowed_method(decoded_method.value, config);
    if (!method)
        return reject(ValidationError::InvalidMethod, RequestMethod::Unknown,
                      decoded_method.value);
    if (!state.received_message &&
        !allowed_initial_method(*method, decoded_method.value, config))
        return reject(ValidationError::InvalidInitialMethod, *method, decoded_method.value);
    if (!valid_sequence(*method, state))
        return reject(ValidationError::InvalidSequence, *method, decoded_method.value);
    if (envelope.id) {
        const ValidationError id_error = valid_id(envelope.id->str);
        if (id_error != ValidationError::None)
            return reject(id_error, *method, decoded_method.value);
    }

    RawParams params;
    if (envelope.params) {
        if (glz::read_json(params, envelope.params->str))
            return reject(ValidationError::InvalidParams, *method, decoded_method.value);
    }
    if (const ValidationError params_error = valid_params(*method, params);
        params_error != ValidationError::None)
        return reject(params_error, *method, decoded_method.value);
    return {.error = ValidationError::None, .method = *method, .rejected_method = {}};
}

void record_request(ProtocolState& state, RequestMethod method) noexcept {
    state.received_message = true;
    if (method == RequestMethod::Subscribe)
        state.subscribed = true;
    else if (method == RequestMethod::Authorize)
        state.authorized = true;
    else if (method == RequestMethod::Resume)
        state.resumed = true;
}

void record_request(ProtocolState& state, std::string_view method) noexcept {
    record_request(state, built_in_method(method));
}

std::string_view validation_error_name(ValidationError error) {
    switch (error) {
    case ValidationError::None:
        return "none";
    case ValidationError::Empty:
        return "empty";
    case ValidationError::TooDeep:
        return "too_deep";
    case ValidationError::InvalidJson:
        return "invalid_json";
    case ValidationError::InvalidShape:
        return "invalid_shape";
    case ValidationError::InvalidMethod:
        return "invalid_method";
    case ValidationError::InvalidInitialMethod:
        return "invalid_initial_method";
    case ValidationError::InvalidSequence:
        return "invalid_sequence";
    case ValidationError::InvalidId:
        return "invalid_id";
    case ValidationError::InvalidParams:
        return "invalid_params";
    case ValidationError::Count:
        break;
    }
    return "unknown";
}

} // namespace erikslund::stratum
