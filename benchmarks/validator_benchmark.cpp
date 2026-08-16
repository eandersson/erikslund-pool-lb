// Standalone throughput benchmark for the bounded SV1 validator hot path.
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string_view>
#include <system_error>

#include "core/config.hpp"
#include "stratum/validator.hpp"

namespace {

using Clock = std::chrono::steady_clock;

void run_case(std::string_view name, std::string_view request,
              const erikslund::stratum::ProtocolState& state,
              const erikslund::core::ProtocolConfig& config, std::uint64_t iterations) {
    std::uint64_t checksum = 0;
    constexpr std::uint64_t kWarmupIterations = 10'000;
    for (std::uint64_t iteration = 0; iteration < kWarmupIterations; ++iteration) {
        const auto result = erikslund::stratum::validate_request(request, state, config);
        checksum += static_cast<std::uint64_t>(result.method);
    }

    const auto started = Clock::now();
    for (std::uint64_t iteration = 0; iteration < iterations; ++iteration) {
        const auto result = erikslund::stratum::validate_request(request, state, config);
        if (!result)
            std::abort();
        checksum += static_cast<std::uint64_t>(result.method);
    }
    const auto elapsed = Clock::now() - started;
    const double seconds = std::chrono::duration<double>(elapsed).count();
    const double messages_per_second = static_cast<double>(iterations) / seconds;
    const double nanoseconds_per_message =
        std::chrono::duration<double, std::nano>(elapsed).count() /
        static_cast<double>(iterations);
    std::printf("%-24.*s %12.0f msg/s %8.1f ns/msg checksum=%llu\n",
                static_cast<int>(name.size()), name.data(), messages_per_second,
                nanoseconds_per_message, static_cast<unsigned long long>(checksum));
}

} // namespace

int main(int argument_count, char** arguments) {
    std::uint64_t iterations = 5'000'000;
    if (argument_count == 2) {
        const std::string_view value(arguments[1]);
        const auto [end, error] =
            std::from_chars(value.data(), value.data() + value.size(), iterations);
        if (error != std::errc{} || end != value.data() + value.size() || iterations == 0)
            return 2;
    } else if (argument_count != 1) {
        return 2;
    }

    const erikslund::stratum::ProtocolState initial;
    const erikslund::stratum::ProtocolState established{
        .received_message = true,
        .subscribed = true,
        .authorized = true,
    };
    const erikslund::core::ProtocolConfig standard;
    erikslund::core::ProtocolConfig extended;
    extended.additional_allowed_methods = {"mining.vendor_extension"};

    run_case("initial subscribe",
             R"({"id":1,"method":"mining.subscribe","params":["benchmark/1.0"]})",
             initial, standard, iterations);
    run_case("established submit",
             R"({"id":7,"method":"mining.submit",)"
             R"("params":["worker","job","00000000","time","nonce"]})",
             established, standard, iterations);
    run_case("configured extension",
             R"({"id":9,"method":"mining.vendor_extension","params":["worker",42,true,null]})",
             established, extended, iterations);
    run_case("escaped subscribe",
             R"({"id":1,"method":"mining.\u0073ubscribe","params":[]})", initial,
             standard, iterations);
}
