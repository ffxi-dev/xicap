#include "columns.h"
#include "support.h"

#include <catch2/catch_test_macros.hpp>

using namespace xicap;

namespace
{

auto bytes(const std::vector<std::byte>& b) -> std::span<const uint8_t>
{
    return { reinterpret_cast<const uint8_t*>(b.data()), b.size() };
}

// FORMAT.md's example: three game packets to the client, opcode 0x0DF, 16 bytes each, 10 ms apart, syncs 1 to 3.
const auto EXAMPLE = std::vector<uint8_t>{
    0x00, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdf, 0x01, 0xdf, 0x01, 0xdf, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x30, 0xdf, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdf, 0x08, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0xdf, 0x08, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
};

} // namespace

TEST_CASE("the columns of FORMAT.md's example")
{
    const auto p0      = test::gamePacket(0x0DF, 16, 1, 0);
    const auto p1      = test::gamePacket(0x0DF, 16, 2, 1);
    const auto p2      = test::gamePacket(0x0DF, 16, 3, 2);
    const auto records = std::vector<internal::Record>{
        { .timestamp = 100, .flags = 0, .channel = 0, .opcode = 0x0DF, .data = bytes(p0) },
        { .timestamp = 110, .flags = 0, .channel = 0, .opcode = 0x0DF, .data = bytes(p1) },
        { .timestamp = 120, .flags = 0, .channel = 0, .opcode = 0x0DF, .data = bytes(p2) },
    };
    CHECK(internal::encodeColumns(records, {}) == EXAMPLE);

    internal::DecodedFrame frame;
    internal::decodeColumns(EXAMPLE, 3, 0, 100, frame);
    REQUIRE(frame.packets.size() == 3);
    CHECK(frame.packet(2).timestamp == 120);
    CHECK(std::ranges::equal(frame.packet(1).data, p1));
}

TEST_CASE("columns keep markers, groups, and lengths the header does not give")
{
    const auto a       = test::gamePacket(0x00D, 10, 5, 7); // 10 bytes: the header's size says 8
    const auto b       = std::vector<std::byte>(3, std::byte{ 9 });
    const auto c       = test::gamePacket(0x015, 8, 1, 3);
    const auto records = std::vector<internal::Record>{
        { .timestamp = 1, .flags = 0, .channel = 0, .opcode = 0x00D, .data = bytes(a) },
        { .timestamp = 1, .flags = 0x8020, .channel = 7, .opcode = 0x1234, .data = bytes(b) },
        { .timestamp = 9, .flags = 1, .channel = 0, .opcode = 0x015, .data = bytes(c) },
        { .timestamp = 9, .flags = 0, .channel = 0, .opcode = 0x00D, .data = bytes(a) },
    };
    const auto markers = std::vector<internal::MarkerRecord>{ { 0, MarkerKind::Login, "" }, { 2, MarkerKind::Note, "x" }, { 2, static_cast<MarkerKind>(9), "y" } };
    const auto plain   = internal::encodeColumns(records, markers);

    internal::DecodedFrame frame;
    internal::decodeColumns(plain, 4, 3, 1, frame);
    REQUIRE(frame.packets.size() == 4);
    for (size_t i = 0; i < records.size(); ++i)
    {
        const auto p = frame.packet(i);
        CHECK(p.flags == records[i].flags);
        CHECK(p.channel == records[i].channel);
        CHECK(p.opcode == records[i].opcode);
        CHECK(std::ranges::equal(std::as_bytes(records[i].data), p.data));
    }
    CHECK(frame.packet(0).markers.size() == 1);
    CHECK(frame.packet(2).markers.size() == 2);
    CHECK(frame.packet(2).markers[1].text == "y");
}

TEST_CASE("a bad plaintext is refused")
{
    internal::DecodedFrame frame;
    auto                   plain = EXAMPLE;
    CHECK_THROWS_AS(internal::decodeColumns(plain, 4, 0, 0, frame), Error); // more packets than it holds
    CHECK_THROWS_AS(internal::decodeColumns(plain, 3, 1, 0, frame), Error); // a marker it does not hold
    plain.push_back(0);
    CHECK_THROWS_AS(internal::decodeColumns(plain, 3, 0, 0, frame), Error); // bytes left over
    plain    = EXAMPLE;
    plain[0] = 1;
    CHECK_THROWS_AS(internal::decodeColumns(plain, 3, 0, 0, frame), Error); // the first delta is not 0
    plain    = EXAMPLE;
    plain[9] = 0xE0;
    CHECK_THROWS_AS(internal::decodeColumns(plain, 3, 0, 0, frame), Error); // an opcode its header does not hold
    plain    = EXAMPLE;
    plain[1] = 0x8A;
    CHECK_THROWS_AS(internal::decodeColumns(plain, 3, 0, 0, frame), Error); // a varint running on
}
