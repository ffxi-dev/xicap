#include "format/layout.h"
#include "support.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <span>

using namespace xicap;

namespace
{

auto writeSample(const std::filesystem::path& path, const Metadata& metadata = test::metadata()) -> void
{
    Writer w(path, metadata);
    for (uint16_t i{ 0 }; i < 2000; ++i)
    {
        if (i % 100 == 0)
        {
            w.mark(MarkerKind::Note, "every hundred");
        }

        w.write(test::packet(i, test::gamePacket(0x017, 40, i, static_cast<uint8_t>(i))));
    }

    w.close();
}

} // namespace

TEST_CASE("transcode keeps the metadata, packets, and markers")
{
    const test::TempFile src;
    const test::TempFile dst;
    writeSample(src);
    transcode(src, dst);
    CHECK(Reader(dst).metadata() == Reader(src).metadata());
    CHECK(test::readAll(dst) == test::readAll(src));
    CHECK(Reader(dst).complete());
}

TEST_CASE("transcode completes a cut-off capture")
{
    const test::TempFile src;
    const test::TempFile dst;
    writeSample(src);
    auto bytes = test::bytesOf(src);
    bytes.resize(bytes.size() - sizeof(format::Trailer));
    test::save(src, bytes);
    REQUIRE_FALSE(Reader(src).complete());
    transcode(src, dst);
    CHECK(test::readAll(dst) == test::readAll(src));
    CHECK(Reader(dst).complete());
}

TEST_CASE("transcode keeps blocks in their order")
{
    const test::TempFile src;
    const test::TempFile dst;
    auto                 m = test::metadata();
    m.source               = Source{ .format = "captain", .formatVersion = "1.2", .skippedRecords = 0, .metadata = {} };
    m.blocks               = { { .type = 0x8001, .payload = { 1 } }, { .type = 0x8001, .payload = { 2 } }, { .type = 0x9000, .payload = {} } };
    m.sourceIndex          = 1;
    writeSample(src, m);
    transcode(src, dst);
    const Reader r(dst);
    CHECK(r.metadata().blocks == m.blocks);
    CHECK(r.metadata().sourceIndex == 1);
    CHECK(r.metadata().source == m.source);
}

TEST_CASE("transcode refuses one file as both source and destination, and keeps a destination it did not open")
{
    const test::TempFile src;
    writeSample(src);
    const auto before = test::bytesOf(src);
    CHECK_THROWS_AS(transcode(src, src), Error);
    CHECK(test::bytesOf(src) == before);

    const test::TempFile missing;
    CHECK_THROWS_AS(transcode(missing, src), Error);
    CHECK(test::bytesOf(src) == before);
}

TEST_CASE("transcode with Chat::Redact zeroes and flags chat, and keeps every other packet")
{
    const test::TempFile src;
    const test::TempFile dst;
    {
        Writer w(src, test::metadata(), FramePolicy::live(), Chat::Keep);
        w.write(test::packet(0, test::gamePacket(0x017, 40, 0, 'x')));
        w.write(test::packet(1, test::gamePacket(0x00A, 40, 1, 'x')));
        w.close();
    }
    transcode(src, dst, FramePolicy::archive(), Chat::Redact);
    const auto before = test::readAll(src);
    const auto after  = test::readAll(dst);
    REQUIRE(after.size() == 2);
    CHECK((after[0].flags & PacketFlag::Redacted) != 0);
    CHECK(after[0].data.size() == before[0].data.size());
    CHECK(std::ranges::all_of(std::span(after[0].data).subspan(0x17), [](const uint8_t b)
                              {
                                  return b == 0;
                              }));
    CHECK(after[1] == before[1]);
    CHECK(Reader(dst).metadata() == Reader(src).metadata());
}
