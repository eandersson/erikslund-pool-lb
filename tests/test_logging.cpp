#include <doctest/doctest.h>

#include <cstddef>
#include <cstdio>
#include <string>

#include <unistd.h>

#include "core/logging.hpp"

TEST_CASE("logger gates levels and emits the Erikslund line shape") {
    std::FILE* capture = std::tmpfile();
    REQUIRE(capture != nullptr);
    const int saved_stderr = ::dup(STDERR_FILENO);
    REQUIRE(saved_stderr >= 0);
    REQUIRE(::dup2(::fileno(capture), STDERR_FILENO) >= 0);

    const erikslund::core::log::Level original_level = erikslund::core::log::level();
    erikslund::core::log::set_level(erikslund::core::log::Level::Info);
    erikslund::core::log::debug("hidden-{}", 1);
    erikslund::core::log::info("visible-{}", 42);
    erikslund::core::log::set_level(original_level);
    std::fflush(stderr);
    REQUIRE(::dup2(saved_stderr, STDERR_FILENO) >= 0);
    ::close(saved_stderr);

    REQUIRE(std::fseek(capture, 0, SEEK_END) == 0);
    const long byte_count = std::ftell(capture);
    REQUIRE(byte_count >= 0);
    std::rewind(capture);
    std::string output(static_cast<std::size_t>(byte_count), '\0');
    CHECK(std::fread(output.data(), 1, output.size(), capture) == output.size());
    std::fclose(capture);

    CHECK(output.starts_with('['));
    CHECK(output.find("hidden-1") == std::string::npos);
    CHECK(output.find("] INFO    visible-42\n") != std::string::npos);
}
