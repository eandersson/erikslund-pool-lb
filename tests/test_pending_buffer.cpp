#include <doctest/doctest.h>

#include <string>
#include <string_view>

#include "net/pending_buffer.hpp"

TEST_CASE("pending buffer preserves unread bytes across appends and compaction") {
    erikslund::net::PendingBuffer buffer;
    buffer.append("abcdef");
    buffer.consume(2);
    buffer.append("ghi");
    CHECK(std::string_view(buffer.data(), buffer.size()) == "cdefghi");

    buffer.consume(4);
    CHECK(std::string_view(buffer.data(), buffer.size()) == "ghi");
    buffer.consume(3);
    CHECK(buffer.empty());
}

TEST_CASE("pending buffer releases burst capacity after it drains") {
    erikslund::net::PendingBuffer buffer;
    buffer.append(std::string(16'384, 'x'));
    REQUIRE(buffer.capacity() > erikslund::net::kMaximumRetainedBufferBytes);
    buffer.consume(buffer.size());
    CHECK(buffer.empty());
    CHECK(buffer.capacity() <= erikslund::net::kMaximumRetainedBufferBytes);
}

TEST_CASE("pending buffer compacts a consumed prefix before appending") {
    erikslund::net::PendingBuffer buffer;
    buffer.append(std::string(10'000, 'x'));
    buffer.consume(6'000);
    buffer.append("tail");
    REQUIRE(buffer.size() == 4'004);
    CHECK(std::string_view(buffer.data(), buffer.size()).ends_with("tail"));
}

TEST_CASE("pending buffer prepends framing before unread bytes") {
    erikslund::net::PendingBuffer buffer;
    buffer.append("discardpayload");
    buffer.consume(7);
    buffer.prepend("frame:");
    CHECK(std::string_view(buffer.data(), buffer.size()) == "frame:payload");

    buffer.consume(buffer.size());
    buffer.append("payload");
    buffer.prepend("frame:");
    CHECK(std::string_view(buffer.data(), buffer.size()) == "frame:payload");
}

TEST_CASE("line buffers retain only their current small content after a burst") {
    std::string line(16'384, 'x');
    line.replace(0, line.size() - 4, "");
    REQUIRE(line == "xxxx");
    REQUIRE(line.capacity() > erikslund::net::kMaximumRetainedBufferBytes);
    erikslund::net::release_oversized_string(line);
    CHECK(line == "xxxx");
    CHECK(line.capacity() <= erikslund::net::kMaximumRetainedBufferBytes);
}
