#include "support.h"

#include <catch2/catch_test_macros.hpp>

using namespace xicap;

namespace
{

auto writeSample(const std::filesystem::path& path, bool close) -> void
{
    Writer w(path, test::metadata());
    for (uint16_t i{ 0 }; i < 2000; ++i)
    {
        if (i % 100 == 0)
        {
            w.mark(MarkerKind::Note, "every hundred");
        }

        w.write(test::out(i, test::gamePacket(0x017, 40, i, static_cast<uint8_t>(i))));
    }

    w.flush();
    if (close)
    {
        w.close();
    }
}

} // namespace

TEST_CASE("transcode keeps the metadata, packets, and markers")
{
    const test::TempFile src;
    const test::TempFile dst;
    writeSample(src, true);
    transcode(src, dst);
    CHECK(Reader(dst).metadata() == Reader(src).metadata());
    CHECK(test::readAll(dst) == test::readAll(src));
    CHECK(Reader(dst).complete());
}

TEST_CASE("transcode completes a cut-off capture")
{
    const test::TempFile src;
    const test::TempFile dst;
    writeSample(src, false);
    transcode(src, dst);
    CHECK(test::readAll(dst) == test::readAll(src));
    CHECK(Reader(dst).complete());
}
