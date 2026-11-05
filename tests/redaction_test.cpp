#include "redaction/redaction.h"
#include "support.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

using namespace xicap;

TEST_CASE("redaction zeroes chat text and keeps the packet's layout")
{
    const auto chat   = test::gamePacket(0x017, 40, 3, 0x41);
    const auto stored = redaction::apply(test::out(1, chat), Chat::Redact);
    CHECK(stored.flags == PacketFlag::Redacted);
    REQUIRE(stored.data.size() == chat.size());
    CHECK(std::ranges::equal(std::span{ stored.data }.first(0x17), std::span{ chat }.first(0x17)));
    CHECK(std::ranges::all_of(std::span{ stored.data }.subspan(0x17), [](const std::byte b)
                              {
                                  return b == std::byte{ 0 };
                              }));
}

TEST_CASE("redaction leaves other packets and directions alone, and kept chat whole")
{
    const auto p = test::gamePacket(0x017, 40, 3, 0x41);
    CHECK(std::ranges::equal(redaction::apply(test::out(1, p, PacketDirection::ClientToServer), Chat::Redact).data, p));
    const auto kept = redaction::apply(test::out(1, p), Chat::Keep);
    CHECK(kept.flags == 0);
    CHECK(std::ranges::equal(kept.data, p));
}
