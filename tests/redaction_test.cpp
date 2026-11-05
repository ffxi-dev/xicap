#include "support.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>

using namespace xicap;

namespace
{

struct Row
{
    PacketDirection direction;
    uint16_t        opcode;
    size_t          offset;
    size_t          length; // 0 runs to the packet's end
};

// FORMAT.md's Redaction table.
constexpr Row ROWS[] = {
    { .direction = PacketDirection::ServerToClient, .opcode = 0x017, .offset = 0x17, .length = 0 },
    { .direction = PacketDirection::ClientToServer, .opcode = 0x0B5, .offset = 0x06, .length = 0 },
    { .direction = PacketDirection::ClientToServer, .opcode = 0x0B6, .offset = 0x15, .length = 0 },
    { .direction = PacketDirection::ClientToServer, .opcode = 0x0B7, .offset = 0x15, .length = 0 },
    { .direction = PacketDirection::ServerToClient, .opcode = 0x0CC, .offset = 0x08, .length = 128 },
    { .direction = PacketDirection::ClientToServer, .opcode = 0x0E2, .offset = 0x10, .length = 128 },
};

auto zero(const std::span<const uint8_t> bytes) -> bool
{
    return std::ranges::all_of(bytes, [](const uint8_t b)
                               {
                                   return b == 0;
                               });
}

auto untouched(const std::span<const uint8_t> bytes) -> bool
{
    return std::ranges::all_of(bytes, [](const uint8_t b)
                               {
                                   return b == 0x41;
                               });
}

} // namespace

TEST_CASE("redaction zeroes each table entry's text and nothing else")
{
    for (const auto& row : ROWS)
    {
        auto       p   = test::gamePacket(row.opcode, 200, 0, 0x41);
        const auto end = row.length == 0 ? p.size() : row.offset + row.length;
        CHECK(redact(p, row.direction));
        CHECK(untouched(std::span{ p }.subspan(4, row.offset - 4)));
        CHECK(zero(std::span{ p }.subspan(row.offset, end - row.offset)));
        CHECK(untouched(std::span{ p }.subspan(end)));
    }
}

TEST_CASE("redaction leaves other packets and directions alone")
{
    auto       p    = test::gamePacket(0x017, 40, 3, 0x41);
    const auto copy = p;
    CHECK_FALSE(redact(p, PacketDirection::ClientToServer));
    CHECK(p == copy);
    auto other = test::gamePacket(0x00D, 40, 3, 0x41);
    CHECK_FALSE(redact(other, PacketDirection::ServerToClient));
}

TEST_CASE("a table packet shorter than its text offset is still in the table")
{
    auto       p    = test::gamePacket(0x017, 16, 3, 0x41);
    const auto copy = p;
    CHECK(redact(p, PacketDirection::ServerToClient));
    CHECK(p == copy);
}

TEST_CASE("a writer redacts chat unless it keeps chat")
{
    const auto chat = test::gamePacket(0x017, 40, 3, 0x41);
    for (const auto keep : { Chat::Redact, Chat::Keep })
    {
        const test::TempFile file;
        {
            Writer w(file, test::metadata(), FramePolicy::live(), keep);
            w.write(test::packet(1, chat));
        }

        const auto packets = test::readAll(file);
        REQUIRE(packets.size() == 1);
        CHECK(packets[0].flags == (keep == Chat::Redact ? PacketFlag::Redacted : 0));
        CHECK(std::ranges::equal(std::span{ packets[0].data }.first(0x17), std::span{ chat }.first(0x17)));
        CHECK((keep == Chat::Redact) == zero(std::span{ packets[0].data }.subspan(0x17)));
    }
}
