#include "support.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

using namespace xicap;

TEST_CASE("the default policy zeroes chat text and keeps the packet's layout")
{
    auto       chat   = test::gamePacket(0x017, 40, 3, 0x41);
    const auto stored = applyPolicy(defaultExclusionPolicy(), test::out(1, chat));
    CHECK(stored.flags == PacketFlag::Redacted);
    REQUIRE(stored.data.size() == chat.size());
    CHECK(std::ranges::equal(std::span{ stored.data }.first(0x17), std::span{ chat }.first(0x17)));
    CHECK(std::ranges::all_of(std::span{ stored.data }.subspan(0x17), [](std::byte b)
                              {
                                  return b == std::byte{ 0 };
                              }));
}

TEST_CASE("the default policy leaves other packets and directions alone")
{
    const auto p = test::gamePacket(0x017, 40, 3, 0x41);
    CHECK(applyPolicy(defaultExclusionPolicy(), test::out(1, p, PacketDirection::ClientToServer)).data == p);
    CHECK(applyPolicy(ExclusionPolicy{}, test::out(1, p)).data == p);
}

TEST_CASE("a stub keeps the 4-byte header")
{
    const auto policy = ExclusionPolicy{ .name = "stub", .version = 1, .rules = { { .channel = 0, .direction = ExclusionDirection::Both, .action = ExclusionAction::Stub, .opcode = 0x0B6, .ranges = {} } } };
    const auto p      = test::gamePacket(0x0B6, 40, 3, 0x41);
    const auto stored = applyPolicy(policy, test::out(1, p, PacketDirection::ClientToServer));
    CHECK(stored.flags == (PacketFlag::Excluded | PacketFlag::ClientToServer));
    CHECK(stored.data == std::vector(p.begin(), p.begin() + 4));
}

TEST_CASE("a writer refuses a policy it cannot apply")
{
    const test::TempFile file;
    auto                 m = test::metadata();
    m.policy.rules.push_back({ .channel = 0, .direction = ExclusionDirection::Both, .action = ExclusionAction::ZeroRange, .opcode = 1, .ranges = { { 2, 4 } } });
    CHECK_THROWS_AS(Writer(file, m), Error);
    m.policy.rules.back() = { .channel = 1, .direction = ExclusionDirection::Both, .action = ExclusionAction::Stub, .opcode = 1, .ranges = {} };
    CHECK_THROWS_AS(Writer(file, m), Error);
}
