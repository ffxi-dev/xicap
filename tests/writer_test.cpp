#include "support.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

using namespace xicap;

TEST_CASE("a capture reads back as written")
{
    const test::TempFile file;
    auto                 m = test::metadata();
    m.previousCaptureId    = { 9 };
    m.source               = Source{ .format = "captain", .formatVersion = "1.2", .skippedRecords = 3, .metadata = { 'h', 'i' } };
    const auto a           = test::gamePacket(0x00D, 64, 7, 0xAA);
    const auto b           = test::gamePacket(0x015, 32, 1, 0xBB);
    const auto search      = std::vector<std::byte>(20, std::byte{ 5 });
    {
        Writer w(file, m);
        w.mark(MarkerKind::Login);
        w.write(test::out(1000, a));
        w.write(test::out(1010, b, PacketDirection::ClientToServer));
        w.mark(MarkerKind::Note, "cap start fight");
        w.write({ .timestamp = 1020, .direction = PacketDirection::ServerToClient, .data = search, .channel = 1, .opcode = 0x0B, .provenance = PacketFlag::Injected });
        w.close();
    }

    const Reader r(file);
    CHECK(r.complete());
    CHECK(r.packetCount() == 3);
    CHECK(r.endTimestamp() == 1020);
    m.startTimestamp = 1000;
    CHECK(r.metadata() == m);

    const auto packets = test::readAll(file);
    REQUIRE(packets.size() == 3);
    CHECK(std::ranges::equal(packets[0].data, a));
    CHECK(packets[0].markers == std::vector<Marker>{ { MarkerKind::Login, "" } });
    CHECK(packets[1].flags == PacketFlag::ClientToServer);
    CHECK(packets[1].opcode == 0x015);
    CHECK(packets[2].channel == 1);
    CHECK(packets[2].opcode == 0x0B);
    CHECK(packets[2].flags == PacketFlag::Injected);
    CHECK(packets[2].markers == std::vector<Marker>{ { MarkerKind::Note, "cap start fight" } });
}

TEST_CASE("an empty capture has a header, its blocks, and a trailer")
{
    const test::TempFile file;
    Writer(file, test::metadata()).close();
    const Reader r(file);
    CHECK(r.complete());
    CHECK(r.metadata().startTimestamp == 0);
    CHECK(test::readAll(file).empty());
}

TEST_CASE("timestamps never go backwards")
{
    const test::TempFile file;
    {
        Writer     w(file, test::metadata());
        const auto p = test::gamePacket(0x00D, 8, 0);
        w.write(test::out(500, p));
        w.write(test::out(400, p));
    }

    const auto packets = test::readAll(file);
    CHECK(packets[1].timestamp == 500);
}

TEST_CASE("frames end at the policy's limits, and each is readable once flushed")
{
    const test::TempFile file;
    auto                 policy = FramePolicy::live();
    policy.maxPacketsPerFrame   = 2;
    Writer     w(file, test::metadata(), policy);
    const auto p = test::gamePacket(0x00D, 8, 0);
    for (uint64_t t{ 0 }; t < 5; ++t)
    {
        w.write(test::out(t, p));
    }

    w.flush();
    CHECK(test::readAll(file).size() == 5);
    CHECK_FALSE(Reader(file).complete());
}

TEST_CASE("a marker with no packet after it is dropped")
{
    const test::TempFile file;
    {
        Writer w(file, test::metadata());
        w.write(test::out(1, test::gamePacket(0x00D, 8, 0)));
        w.mark(MarkerKind::Logout);
    }

    CHECK(test::readAll(file)[0].markers.empty());
}

TEST_CASE("text fields are cut between characters")
{
    const test::TempFile file;
    auto                 m = test::metadata();
    m.character.name       = "abcdefghijklmn\xC3\xA9"; // 16 bytes: the é does not fit in 15
    Writer(file, m).close();
    CHECK(Reader(file).metadata().character.name == "abcdefghijklmn");
}

TEST_CASE("a writer refuses a game packet under 4 bytes and a closed writer refuses packets")
{
    const test::TempFile file;
    Writer               w(file, test::metadata());
    const auto           tiny = std::vector<std::byte>(3);
    CHECK_THROWS_AS(w.write(test::out(1, tiny)), Error);
    w.close();
    CHECK_THROWS_AS(w.write(test::out(1, test::gamePacket(0x00D, 8, 0))), Error);
}

TEST_CASE("a writer refuses metadata and frame policies outside the format, before it opens the file")
{
    const test::TempFile file;
    auto                 m = test::metadata();
    m.source               = Source{ .format = "captain", .formatVersion = "1", .skippedRecords = 0, .metadata = std::vector<uint8_t>(16 * 1024 * 1024) };
    CHECK_THROWS_AS(Writer(file, m), Error);
    m.source.reset();
    m.blocks = std::vector<Block>(256, Block{ .type = 0x8001, .payload = {} });
    CHECK_THROWS_AS(Writer(file, m), Error);

    auto policy               = FramePolicy::live();
    policy.maxPacketsPerFrame = 1024 * 1024 + 1;
    CHECK_THROWS_AS(Writer(file, test::metadata(), policy), Error);
    policy           = FramePolicy::live();
    policy.windowLog = 24;
    CHECK_THROWS_AS(Writer(file, test::metadata(), policy), Error);
    CHECK_FALSE(std::filesystem::exists(file));

    Writer(file, test::metadata(), FramePolicy::archive()).close();
    CHECK(Reader(file).complete());
}
