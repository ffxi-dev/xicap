#include "support.h"

#include <catch2/catch_test_macros.hpp>

using namespace xicap;

namespace
{

auto writeSample(const std::filesystem::path& path) -> void
{
    auto policy               = FramePolicy::live();
    policy.maxPacketsPerFrame = 3;
    Writer w(path, test::metadata(), policy);
    for (uint16_t i{ 0 }; i < 10; ++i)
    {
        w.write(test::out(uint64_t{ 10 } * i, test::gamePacket(0x00D, 24, i, static_cast<uint8_t>(i))));
    }

    w.close();
}

} // namespace

TEST_CASE("a cut-off file reads up to its last whole frame, wherever it was cut")
{
    const test::TempFile whole;
    writeSample(whole);
    const auto bytes = test::bytesOf(whole);
    const auto all   = test::readAll(whole);

    const test::TempFile cut;
    Writer(cut, test::metadata()).close();
    const auto blocksEnd = std::filesystem::file_size(cut.path()) - 24;
    size_t     previous{ 0 };
    for (auto size = blocksEnd; size < bytes.size(); ++size)
    {
        test::save(cut, { bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(size) });
        const auto packets = test::readAll(cut);
        const auto first   = std::vector(all.begin(), all.begin() + static_cast<std::ptrdiff_t>(packets.size()));
        CHECK(packets == first);
        CHECK(packets.size() >= previous);
        CHECK_FALSE(Reader(cut).complete());
        previous = packets.size();
    }

    CHECK(previous == all.size());
}

TEST_CASE("a file that is not a whole capture start is refused")
{
    const test::TempFile file;
    writeSample(file);
    auto bytes = test::bytesOf(file);
    bytes.resize(100);
    test::save(file, bytes);
    CHECK_THROWS_AS(Reader(file), Error);
    CHECK_THROWS_AS(Reader("no such file"), Error);
}

TEST_CASE("a reader refuses bytes after a trailer that ends a read chunk")
{
    // 160 bytes of header, a 65,340-byte block with its 12 bytes of framing, and a 24-byte trailer: 64 KiB.
    const test::TempFile file;
    auto                 m = test::metadata();
    m.blocks               = { { .type = 0x8001, .payload = std::vector<uint8_t>(65'340) } };
    Writer(file, m).close();
    auto bytes = test::bytesOf(file);
    REQUIRE(bytes.size() == size_t{ 64 } * 1024);
    CHECK(test::readAll(file).empty());
    bytes.push_back(0);
    test::save(file, bytes);
    CHECK_THROWS_AS(test::readAll(file), Error);
}
