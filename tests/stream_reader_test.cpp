#include "support.h"

#include <catch2/catch_test_macros.hpp>

using namespace xicap;

TEST_CASE("a stream reader fed a byte at a time reads what the reader reads")
{
    const test::TempFile file;
    {
        auto policy               = FramePolicy::live();
        policy.maxPacketsPerFrame = 2;
        Writer w(file, test::metadata(), policy);
        w.mark(MarkerKind::Login);
        for (uint16_t i = 0; i < 7; ++i)
        {
            w.write(test::out(i, test::gamePacket(0x00D, 12, i, 1)));
        }
    }
    const auto bytes = test::bytesOf(file);

    StreamReader             s;
    std::vector<test::Owned> packets;
    Packet                   p;
    for (const auto b : bytes)
    {
        CHECK_FALSE(s.complete());
        s.push(std::as_bytes(std::span{ &b, 1 }));
        while (s.next(p))
        {
            packets.emplace_back(p);
        }
    }
    CHECK(s.complete());
    CHECK_FALSE(s.stopped());
    CHECK(s.bytesRead() == bytes.size());
    CHECK(s.metadata() == Reader(file).metadata());
    CHECK(packets == test::readAll(file));
    CHECK_THROWS_AS(s.push(std::as_bytes(std::span{ bytes }.first(1))), Error);
}

TEST_CASE("a stream reader stops at bytes that are not a frame")
{
    const test::TempFile file;
    Writer               w(file, test::metadata());
    w.write(test::out(1, test::gamePacket(0x00D, 12, 0)));
    w.flush();
    auto bytes = test::bytesOf(file);
    bytes.insert(bytes.end(), { 'j', 'u', 'n', 'k' });

    StreamReader s;
    s.push(std::as_bytes(std::span{ bytes }));
    Packet p;
    CHECK(s.next(p));
    CHECK_FALSE(s.next(p));
    CHECK(s.stopped());
    CHECK(s.bytesRead() == bytes.size() - 4);
}
