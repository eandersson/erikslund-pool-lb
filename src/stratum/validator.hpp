#pragma once
// Bounded Stratum V1 JSON-RPC validation for untrusted miner input.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "core/config.hpp"

namespace erikslund::stratum {

enum class ValidationError : std::uint8_t {
    None,
    Empty,
    TooDeep,
    InvalidJson,
    InvalidShape,
    InvalidMethod,
    InvalidInitialMethod,
    InvalidSequence,
    InvalidId,
    InvalidParams,
    Count,
};

enum class RequestMethod : std::uint8_t {
    Unknown,
    Authorize,
    Capabilities,
    Configure,
    ExtranonceSubscribe,
    GetTransactions,
    MultiVersion,
    Resume,
    Submit,
    Subscribe,
    SuggestDifficulty,
    SuggestTarget,
    UpdatePassword,
    Extension,
    Response,
};

struct ProtocolState {
    bool received_message = false;
    bool subscribed = false;
    bool authorized = false;
    bool resumed = false;
};

inline constexpr std::size_t kValidationErrorCount =
    static_cast<std::size_t>(ValidationError::Count);

struct ValidationResult {
    ValidationError error = ValidationError::None;
    RequestMethod method = RequestMethod::Unknown;
    // Successful requests stay allocation-free at the result boundary. Rejections retain the
    // decoded method for diagnostics without making every accepted share copy its method name.
    std::string rejected_method;

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == ValidationError::None;
    }
};

ValidationResult validate_request(std::string_view line, const ProtocolState& state,
                                   const core::ProtocolConfig& config);
void record_request(ProtocolState& state, RequestMethod method) noexcept;
void record_request(ProtocolState& state, std::string_view method) noexcept;
std::string_view validation_error_name(ValidationError error);

} // namespace erikslund::stratum
