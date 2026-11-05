#include "support.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

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
    const auto search      = std::vector<uint8_t>(20, 5);
    {
        Writer w(file, m);
        w.mark(MarkerKind::Login);
        w.write(test::packet(1000, a));
        w.write(test::packet(1010, b, PacketDirection::ClientToServer));
        w.mark(MarkerKind::Note, "cap start fight");
        w.write({ .timestamp = 1020, .direction = PacketDirection::ServerToClient, .provenance = PacketFlag::Injected, .channel = Channel::Search, .opcode = 0x0B, .data = search });
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
    CHECK(packets[2].channel == Channel::Search);
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
        w.write(test::packet(500, p));
        w.write(test::packet(400, p));
    }

    const auto packets = test::readAll(file);
    REQUIRE(packets.size() == 2);
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
        w.write(test::packet(t, p));
    }

    CHECK(test::readAll(file).size() == 4); // two full frames; the fifth packet waits
    w.flush();
    CHECK(test::readAll(file).size() == 5);
    CHECK_FALSE(Reader(file).complete());
}

TEST_CASE("a live writer ends a frame once it spans 5 seconds")
{
    const test::TempFile file;
    Writer               w(file, test::metadata());
    const auto           p = test::gamePacket(0x00D, 8, 0);
    w.write(test::packet(0, p));
    CHECK(std::filesystem::file_size(file) == 0); // the header goes out with the first frame
    w.write(test::packet(5000, p));
    CHECK(test::readAll(file).size() == 1);
}

TEST_CASE("a marker with no packet after it is dropped")
{
    const test::TempFile file;
    {
        Writer w(file, test::metadata());
        w.write(test::packet(1, test::gamePacket(0x00D, 8, 0)));
        w.mark(MarkerKind::Logout);
    }

    const auto packets = test::readAll(file);
    REQUIRE(packets.size() == 1);
    CHECK(packets[0].markers.empty());
}

TEST_CASE("a refused copy leaves no markers behind")
{
    const test::TempFile file;
    {
        Writer     w(file, test::metadata());
        const auto marker = std::vector<Marker>{ { .kind = MarkerKind::Note, .text = "lost" } };
        const auto tiny   = std::vector<uint8_t>(3);
        CHECK_THROWS_AS(w.copy({ .timestamp = 1, .flags = 0, .channel = Channel::Game, .opcode = 0, .data = tiny, .markers = marker }), Error);
        w.write(test::packet(2, test::gamePacket(0x00D, 8, 0)));
    }

    const auto packets = test::readAll(file);
    REQUIRE(packets.size() == 1);
    CHECK(packets[0].markers.empty());
}

TEST_CASE("close reports an earlier failed write")
{
    if (!std::filesystem::exists("/dev/full"))
    {
        SKIP("needs /dev/full");
    }

    Writer w("/dev/full", test::metadata());
    w.write(test::packet(1, test::gamePacket(0x00D, 8, 0)));
    CHECK_THROWS_AS(w.flush(), Error);
    CHECK_THROWS_WITH(w.close(), "xicap: an earlier write failed");
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
    const auto           tiny = std::vector<uint8_t>(3);
    CHECK_THROWS_AS(w.write(test::packet(1, tiny)), Error);
    w.close();
    CHECK_THROWS_AS(w.write(test::packet(1, test::gamePacket(0x00D, 8, 0))), Error);
}

TEST_CASE("a writer refuses metadata and frame policies outside the format, before it opens the file")
{
    const test::TempFile file;
    auto                 m = test::metadata();
    m.source               = Source{ .format = "captain", .formatVersion = "1", .skippedRecords = 0, .metadata = std::vector<uint8_t>(size_t{ 16 } * 1024 * 1024) };
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
