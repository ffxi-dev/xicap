#include <xicap/xicap.h>

#include "internal/crc32.h"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace
{

inline std::atomic<uint64_t> g_tempCounter{ 0 };

struct TempCapture
{
    fs::path path = fs::temp_directory_path() / fs::path{ "xicap-test-" + std::to_string(g_tempCounter.fetch_add(1)) + ".xicap" };
    ~TempCapture()
    {
        std::error_code ec;
        fs::remove(path, ec);
    }
};

struct OwnedPacket
{
    uint64_t                 timestamp;
    uint16_t                 opcode;
    xicap::PacketDirection   direction;
    std::vector<uint8_t>     data;
    std::vector<std::string> markers;
};

auto materialize(const xicap::ReadPacket& p) -> OwnedPacket
{
    OwnedPacket o;
    o.timestamp       = p.timestamp;
    o.opcode          = p.opcode;
    o.direction       = p.direction;
    const auto* bytes = reinterpret_cast<const uint8_t*>(p.data.data());
    o.data.assign(bytes, bytes + p.data.size());
    for (const auto& m : p.markers)
    {
        o.markers.push_back(m.text);
    }
    return o;
}

auto makePacket(uint16_t opcode, uint16_t size, uint8_t fill) -> std::vector<std::byte>
{
    std::vector<std::byte> p(size);
    const uint16_t         hdr = static_cast<uint16_t>(((size & 0x7F) << 9) | (opcode & 0x1FF));
    p[0]                       = std::byte(hdr & 0xFF);
    p[1]                       = std::byte(hdr >> 8);
    for (size_t i = 4; i < size; ++i)
    {
        p[i] = std::byte(fill);
    }
    return p;
}

auto baseConfig() -> xicap::WriterConfig
{
    xicap::WriterConfig cfg{};
    cfg.clientVersion   = "test-client";
    cfg.captureAgent    = "xicap-tests";
    cfg.startZoneId     = 100;
    cfg.lobby.contentId = 0xDEADBEEF;
    cfg.lobby.worldId   = 42;
    std::memcpy(cfg.lobby.characterName.data(), "TestChar", 8);
    std::memcpy(cfg.lobby.worldName.data(), "Asura", 5);
    return cfg;
}

auto writeNPackets(xicap::Writer& w, int n, uint64_t startTs = 1'700'000'000'000ULL, uint64_t deltaMs = 50) -> void
{
    for (int i = 0; i < n; ++i)
    {
        const auto pkt = makePacket(static_cast<uint16_t>(0x100 + (i % 4)), 32, static_cast<uint8_t>(i));
        w.write(startTs + i * deltaMs,
                (i % 2) ? xicap::PacketDirection::ClientToServer : xicap::PacketDirection::ServerToClient,
                pkt);
    }
}

// Frames start after the header and every extension block — including the
// EXT_ZSTD_DICT block the writer emits. Tests that poke at raw frame bytes must
// walk the blocks rather than assume sizeof(Header).
auto firstFrameOffset(const fs::path& path) -> uint64_t
{
    std::ifstream f(path, std::ios::binary);
    xicap::Header h{};
    f.read(reinterpret_cast<char*>(&h), sizeof(h));
    uint64_t off = sizeof(xicap::Header);
    for (uint16_t i = 0; i < h.extensionCount; ++i)
    {
        xicap::ExtensionBlockHeader eh{};
        f.seekg(static_cast<std::streamoff>(off));
        f.read(reinterpret_cast<char*>(&eh), sizeof(eh));
        off += sizeof(eh) + eh.length;
    }
    return off;
}

// Rewrites a frame header in place and refreshes the frame CRC so the frame
// stays well-formed apart from the field under test.
template <typename Fn>
auto patchFrameHeader(const fs::path& path, uint64_t frameOffset, Fn mutate) -> void
{
    std::fstream f(path, std::ios::binary | std::ios::in | std::ios::out);
    f.seekg(static_cast<std::streamoff>(frameOffset));
    xicap::FrameHeader fh{};
    f.read(reinterpret_cast<char*>(&fh), sizeof(fh));

    std::vector<uint8_t> payload(fh.compressedSize);
    f.read(reinterpret_cast<char*>(payload.data()), static_cast<std::streamsize>(payload.size()));

    mutate(fh);

    xicap::internal::Crc32 crc;
    crc.update({ reinterpret_cast<const uint8_t*>(&fh), sizeof(fh) });
    crc.update(payload);
    const uint32_t value = crc.value();

    f.seekp(static_cast<std::streamoff>(frameOffset));
    f.write(reinterpret_cast<const char*>(&fh), sizeof(fh));
    f.seekp(static_cast<std::streamoff>(frameOffset + sizeof(fh) + payload.size()));
    f.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

auto readAllOwned(xicap::Reader& r) -> std::vector<OwnedPacket>
{
    std::vector<OwnedPacket> all;
    xicap::ReadPacket        pkt;
    while (r.next(pkt))
    {
        all.push_back(materialize(pkt));
    }
    return all;
}

} // namespace

TEST_CASE("round-trip preserves packet count, opcodes, directions, payloads", "[round-trip]")
{
    TempCapture tmp;
    {
        xicap::Writer w(tmp.path, baseConfig());
        writeNPackets(w, 200);
        w.close();
    }

    xicap::Reader r(tmp.path);
    const auto    pkts = readAllOwned(r);

    REQUIRE(pkts.size() == 200);
    for (size_t i = 0; i < pkts.size(); ++i)
    {
        CHECK(pkts[i].opcode == 0x100 + (i % 4));
        CHECK(pkts[i].direction == ((i % 2) ? xicap::PacketDirection::ClientToServer : xicap::PacketDirection::ServerToClient));
        CHECK(pkts[i].data.size() == 32);
        for (size_t j = 4; j < pkts[i].data.size(); ++j)
        {
            CHECK(pkts[i].data[j] == static_cast<uint8_t>(i));
        }
    }
}

TEST_CASE("clean close writes a footer; truncated capture falls back to scan", "[footer]")
{
    TempCapture tmp;
    {
        xicap::Writer w(tmp.path, baseConfig());
        writeNPackets(w, 250);
        w.close();
    }
    const auto sealedSize = fs::file_size(tmp.path);

    SECTION("clean close: hasFooter() == true and full packets read")
    {
        xicap::Reader r(tmp.path);
        REQUIRE(r.hasFooter());
        REQUIRE(r.totalFrames() > 0);
        const auto pkts = readAllOwned(r);
        CHECK(pkts.size() == 250);
    }

    SECTION("truncated: hasFooter() == false and the readable prefix is recovered")
    {
        const auto truncated = tmp.path.parent_path() / "xicap-trunc.xicap";
        fs::copy_file(tmp.path, truncated, fs::copy_options::overwrite_existing);
        fs::resize_file(truncated, sealedSize - 100);

        {
            xicap::Reader r(truncated);
            CHECK_FALSE(r.hasFooter());
            const auto pkts = readAllOwned(r);
            CHECK_FALSE(pkts.empty());
            CHECK(pkts.size() <= 250);
        }
        fs::remove(truncated);
    }
}

TEST_CASE("invalid magic and bad version rejected with typed error", "[validation]")
{
    TempCapture tmp;
    {
        xicap::Writer w(tmp.path, baseConfig());
        writeNPackets(w, 10);
        w.close();
    }

    SECTION("invalid magic")
    {
        std::fstream f(tmp.path, std::ios::binary | std::ios::in | std::ios::out);
        const char   bogus[4] = { 'N', 'O', 'P', 'E' };
        f.write(bogus, 4);
        f.close();

        try
        {
            xicap::Reader r(tmp.path);
            FAIL("expected throw");
        }
        catch (const xicap::Error& e)
        {
            CHECK(e.code() == xicap::ErrorCode::BadMagic);
        }
    }

    SECTION("unsupported version")
    {
        std::fstream f(tmp.path, std::ios::binary | std::ios::in | std::ios::out);
        f.seekp(4);
        const uint8_t bumped = xicap::VERSION_MAJOR + 1;
        f.write(reinterpret_cast<const char*>(&bumped), 1);
        f.close();

        try
        {
            xicap::Reader r(tmp.path);
            FAIL("expected throw");
        }
        catch (const xicap::Error& e)
        {
            CHECK(e.code() == xicap::ErrorCode::UnsupportedVersion);
        }
    }
}

TEST_CASE("dictionary id mismatch is rejected at open time", "[dict]")
{
    TempCapture tmp;
    {
        xicap::Writer w(tmp.path, baseConfig());
        writeNPackets(w, 10);
        w.close();
    }

    std::fstream f(tmp.path, std::ios::binary | std::ios::in | std::ios::out);
    f.seekp(offsetof(xicap::Header, dictionaryId));
    const uint32_t bogusDictId = 0xDEADBEEF;
    f.write(reinterpret_cast<const char*>(&bogusDictId), sizeof(bogusDictId));
    f.close();

    try
    {
        xicap::Reader r(tmp.path);
        FAIL("expected throw");
    }
    catch (const xicap::Error& e)
    {
        CHECK(e.code() == xicap::ErrorCode::DictionaryMismatch);
    }
}

TEST_CASE("extension blocks round-trip in order", "[extensions]")
{
    TempCapture tmp;
    {
        xicap::Writer  w(tmp.path, baseConfig());
        const uint8_t  payloadA[] = { 1, 2, 3, 4, 5 };
        const uint8_t  payloadB[] = { 'h', 'i' };
        const uint32_t custom     = 0xC0DECAFE;
        w.addExtension(xicap::EXT_PLAYER, std::as_bytes(std::span{ payloadA }));
        w.addExtension(xicap::EXT_LOBBY_SNAPSHOT, std::as_bytes(std::span{ payloadB }));
        w.addExtension(custom, std::as_bytes(std::span{ payloadA }));
        writeNPackets(w, 10);
        w.close();
    }

    xicap::Reader r(tmp.path);
    REQUIRE(r.extensions().size() == 3);

    const auto* p = r.getExtension(xicap::EXT_PLAYER);
    REQUIRE(p != nullptr);
    CHECK(p->data == std::vector<uint8_t>{ 1, 2, 3, 4, 5 });

    const auto* l = r.getExtension(xicap::EXT_LOBBY_SNAPSHOT);
    REQUIRE(l != nullptr);
    CHECK(l->data == std::vector<uint8_t>{ 'h', 'i' });

    const auto* c = r.getExtension(0xC0DECAFE);
    REQUIRE(c != nullptr);
    CHECK(c->data.size() == 5);
}

TEST_CASE("lobby identity round-trips", "[lobby]")
{
    TempCapture tmp;
    {
        auto cfg                = baseConfig();
        cfg.lobby               = {};
        cfg.lobby.contentId     = 0x12345678;
        cfg.lobby.worldId       = 7;
        cfg.lobby.status        = 3;
        cfg.lobby.pendingRename = 1;
        std::memcpy(cfg.lobby.characterName.data(), "Mehdi", 5);
        std::memcpy(cfg.lobby.worldName.data(), "Phoenix", 7);
        xicap::Writer w(tmp.path, cfg);
        writeNPackets(w, 10);
        w.close();
    }

    xicap::Reader r(tmp.path);
    const auto&   l = r.lobby();
    CHECK(l.contentId == 0x12345678);
    CHECK(l.worldId == 7);
    CHECK(l.status == 3);
    CHECK(l.pendingRename == 1);
    CHECK(std::string(l.characterName.data()) == "Mehdi");
    CHECK(std::string(l.worldName.data()) == "Phoenix");
}

TEST_CASE("multi-frame seek by index, time, zone returns SeekResult", "[seek]")
{
    TempCapture tmp;
    {
        xicap::FramePolicy pol{};
        pol.maxPacketsPerFrame = 50;
        xicap::Writer w(tmp.path, baseConfig(), pol);
        writeNPackets(w, 250, 1'700'000'000'000ULL, 100);
        w.close();
    }

    xicap::Reader r(tmp.path);
    REQUIRE(r.totalFrames() >= 5);

    SECTION("seekToFrame jumps to the right starting timestamp")
    {
        REQUIRE(r.seekToFrame(2) == xicap::SeekResult::Ok);
        const auto        expected = r.frameTimestamp(2);
        xicap::ReadPacket pkt;
        REQUIRE(r.next(pkt));
        CHECK(pkt.timestamp == expected);
    }

    SECTION("seekToFrame out of range")
    {
        CHECK(r.seekToFrame(99999) == xicap::SeekResult::OutOfRange);
    }

    SECTION("seekToTime lands on or before the requested ts")
    {
        const uint64_t target = 1'700'000'000'000ULL + 5'000;
        REQUIRE(r.seekToTime(target) == xicap::SeekResult::Ok);
        xicap::ReadPacket pkt;
        REQUIRE(r.next(pkt));
        CHECK(pkt.timestamp >= target);
    }

    SECTION("seekToZone for unknown zone")
    {
        CHECK(r.seekToZone(9999) == xicap::SeekResult::NotFound);
    }
}

TEST_CASE("markers attach to the packet they target", "[markers]")
{
    TempCapture tmp;
    {
        xicap::Writer w(tmp.path, baseConfig());
        writeNPackets(w, 5);
        w.addMarker("after-fifth");
        writeNPackets(w, 3, 1'700'000'001'000ULL);
        w.close();
    }

    xicap::Reader r(tmp.path);
    const auto    pkts = readAllOwned(r);
    REQUIRE(pkts.size() == 8);

    int markerCount = 0;
    for (size_t i = 0; i < pkts.size(); ++i)
    {
        if (i == 4)
        {
            REQUIRE(pkts[i].markers.size() == 1);
            CHECK(pkts[i].markers[0] == "after-fifth");
            markerCount++;
        }
        else
        {
            CHECK(pkts[i].markers.empty());
        }
    }
    CHECK(markerCount == 1);
}

TEST_CASE("addMarker before any packet throws AddMarkerWithoutPacket", "[markers]")
{
    TempCapture   tmp;
    xicap::Writer w(tmp.path, baseConfig());
    try
    {
        w.addMarker("too early");
        FAIL("expected throw");
    }
    catch (const xicap::Error& e)
    {
        CHECK(e.code() == xicap::ErrorCode::AddMarkerWithoutPacket);
    }
}

TEST_CASE("hostile extension length is rejected", "[validation]")
{
    TempCapture tmp;
    {
        xicap::Writer w(tmp.path, baseConfig());
        const uint8_t payload[] = { 1, 2, 3, 4 };
        w.addExtension(xicap::EXT_PLAYER, std::as_bytes(std::span{ payload }));
        writeNPackets(w, 5);
        w.close();
    }

    std::fstream f(tmp.path, std::ios::binary | std::ios::in | std::ios::out);
    f.seekp(sizeof(xicap::Header) + offsetof(xicap::ExtensionBlockHeader, length));
    const uint32_t hostile = 0xC0000000u;
    f.write(reinterpret_cast<const char*>(&hostile), sizeof(hostile));
    f.close();

    try
    {
        xicap::Reader r(tmp.path);
        FAIL("expected throw");
    }
    catch (const xicap::Error& e)
    {
        CHECK(e.code() == xicap::ErrorCode::ShortExtension);
    }
}

TEST_CASE("startTimestamp falls back to first frame when header is unpatched", "[truncation]")
{
    TempCapture tmp;
    uint64_t    expected = 0;
    {
        xicap::Writer w(tmp.path, baseConfig());
        writeNPackets(w, 100, 1'700'000'000'000ULL);
        expected = 1'700'000'000'000ULL;
        w.close();
    }

    std::fstream f(tmp.path, std::ios::binary | std::ios::in | std::ios::out);
    f.seekp(offsetof(xicap::Header, startTimestamp));
    const uint64_t zero = 0;
    f.write(reinterpret_cast<const char*>(&zero), sizeof(zero));
    f.close();

    xicap::Reader r(tmp.path);
    CHECK(r.startTimestamp() == expected);
}

TEST_CASE("end-of-capture metadata is back-patched on clean close", "[end-meta]")
{
    TempCapture    tmp;
    constexpr int  N        = 73;
    const uint64_t startTs  = 1'700'000'000'000ULL;
    const uint64_t deltaMs  = 50;
    const uint64_t expected = startTs + (N - 1) * deltaMs;

    {
        xicap::Writer w(tmp.path, baseConfig());
        writeNPackets(w, N, startTs, deltaMs);
        w.close();
    }

    xicap::Reader r(tmp.path);
    CHECK(r.endTimestamp() == expected);
    CHECK(r.totalPacketCount() == N);
    CHECK(r.endZoneId() == 100); // no zone change, so still the configured start zone
}

TEST_CASE("frame CRC mismatch is detected", "[crc]")
{
    TempCapture tmp;
    {
        xicap::Writer w(tmp.path, baseConfig());
        writeNPackets(w, 10);
        w.close();
    }

    // Flip a bit in the first frame's compressed payload.
    const auto   frameOffset = firstFrameOffset(tmp.path);
    std::fstream f(tmp.path, std::ios::binary | std::ios::in | std::ios::out);
    f.seekg(static_cast<std::streamoff>(frameOffset + sizeof(xicap::FrameHeader) + 4));
    char b = 0;
    f.read(&b, 1);
    f.seekp(static_cast<std::streamoff>(frameOffset + sizeof(xicap::FrameHeader) + 4));
    char flipped = b ^ 0x01;
    f.write(&flipped, 1);
    f.close();

    xicap::Reader     r(tmp.path);
    xicap::ReadPacket pkt;
    try
    {
        r.next(pkt);
        FAIL("expected throw");
    }
    catch (const xicap::Error& e)
    {
        // Either the CRC check trips, or zstd detects a corrupt frame first.
        CHECK((e.code() == xicap::ErrorCode::FrameChecksumMismatch || e.code() == xicap::ErrorCode::DecompressFailed || e.code() == xicap::ErrorCode::CorruptFrame));
    }
}

TEST_CASE("skipCurrentFrame recovers iteration past a corrupt frame", "[recovery]")
{
    TempCapture tmp;
    {
        xicap::FramePolicy pol{};
        pol.maxPacketsPerFrame = 10;
        xicap::Writer w(tmp.path, baseConfig(), pol);
        writeNPackets(w, 30);
        w.close();
    }

    // Corrupt the first frame's CRC by flipping its trailer bytes.
    {
        const auto   frameOffset = firstFrameOffset(tmp.path);
        std::fstream f(tmp.path, std::ios::binary | std::ios::in | std::ios::out);
        f.seekg(0, std::ios::end);
        const auto size = f.tellg();
        REQUIRE(static_cast<uint64_t>(size) > frameOffset + sizeof(xicap::FrameHeader) + 4);
        // Read first frame's compressedSize.
        f.seekg(static_cast<std::streamoff>(frameOffset));
        xicap::FrameHeader fh{};
        f.read(reinterpret_cast<char*>(&fh), sizeof(fh));
        // Position of CRC = after frame header + compressed payload.
        const auto crcPos = static_cast<std::streampos>(frameOffset + sizeof(xicap::FrameHeader) + fh.compressedSize);
        f.seekp(crcPos);
        const uint32_t bogus = 0xBADDCAFE;
        f.write(reinterpret_cast<const char*>(&bogus), sizeof(bogus));
    }

    xicap::Reader     r(tmp.path);
    int               recovered = 0;
    bool              sawError  = false;
    xicap::ReadPacket pkt;
    while (true)
    {
        try
        {
            if (!r.next(pkt))
            {
                break;
            }
            ++recovered;
        }
        catch (const xicap::Error& e)
        {
            sawError = true;
            CHECK(e.code() == xicap::ErrorCode::FrameChecksumMismatch);
            r.skipCurrentFrame();
        }
    }
    CHECK(sawError);
    CHECK(recovered > 0);  // we recovered some packets after the bad frame
    CHECK(recovered < 30); // we lost the first frame
}

TEST_CASE("force flush prevents deltaMs clip on long gaps", "[force-flush]")
{
    TempCapture tmp;
    {
        xicap::Writer w(tmp.path, baseConfig());
        const auto    pkt = makePacket(0x100, 32, 0);
        w.write(1'000'000ULL, xicap::PacketDirection::ServerToClient, pkt);
        // 5 minutes later — far past UINT16_MAX ms.
        w.write(1'000'000ULL + 300'000ULL, xicap::PacketDirection::ServerToClient, pkt);
        w.close();
    }

    xicap::Reader     r(tmp.path);
    xicap::ReadPacket p;
    REQUIRE(r.next(p));
    const auto t0 = p.timestamp;
    REQUIRE(r.next(p));
    const auto t1 = p.timestamp;
    CHECK(t1 - t0 == 300'000ULL); // exact, no clip
    CHECK_FALSE(r.next(p));
    CHECK(r.totalFrames() == 2); // a frame boundary was forced
}

TEST_CASE("packets larger than one frame's uncompressed budget split cleanly", "[frame-split]")
{
    TempCapture tmp;
    {
        xicap::FramePolicy pol{};
        pol.maxFrameSize = 4 * 1024;
        xicap::Writer w(tmp.path, baseConfig(), pol);
        writeNPackets(w, 500);
        w.close();
    }

    xicap::Reader r(tmp.path);
    CHECK(r.totalFrames() > 1);
    const auto pkts = readAllOwned(r);
    CHECK(pkts.size() == 500);
}

TEST_CASE("frames before any LOGIN_ZONE carry the configured start zone", "[zone]")
{
    TempCapture tmp;
    {
        xicap::Writer w(tmp.path, baseConfig()); // startZoneId = 100
        writeNPackets(w, 10);
        w.close();
    }

    xicap::Reader r(tmp.path);
    const auto    zones = r.listZones();
    REQUIRE(zones.size() == 1);
    CHECK(zones[0].zoneId == 100);
    CHECK(r.seekToZone(100) == xicap::SeekResult::Ok);
}

TEST_CASE("the capture's dictionary is embedded and not surfaced as agent data", "[dict]")
{
    TempCapture tmp;
    {
        xicap::Writer w(tmp.path, baseConfig());
        const uint8_t payload[] = { 1, 2, 3 };
        w.addExtension(xicap::EXT_PLAYER, std::as_bytes(std::span{ payload }));
        writeNPackets(w, 10);
        w.close();
    }

    // Header counts the dictionary block; Reader::extensions() does not expose it.
    xicap::Header h{};
    {
        std::ifstream f(tmp.path, std::ios::binary);
        f.read(reinterpret_cast<char*>(&h), sizeof(h));
    }
    CHECK(h.extensionCount == 2);

    xicap::Reader r(tmp.path);
    CHECK(r.extensions().size() == 1);
    CHECK(r.extensions()[0].type == xicap::EXT_PLAYER);
    CHECK(r.getExtension(xicap::EXT_ZSTD_DICT) == nullptr);
    CHECK(readAllOwned(r).size() == 10);
}

TEST_CASE("a capture written with a foreign dictionary still reads", "[dict]")
{
    // Stands in for a capture produced by a build with a different builtin
    // dictionary: the reader must use the bytes in the file, not its own.
    std::vector<uint8_t> foreign(4096);
    for (size_t i = 0; i < foreign.size(); ++i)
    {
        foreign[i] = static_cast<uint8_t>((i * 7) & 0xFF);
    }

    TempCapture tmp;
    {
        xicap::FramePolicy pol{};
        pol.dictionary = foreign;
        xicap::Writer w(tmp.path, baseConfig(), pol);
        writeNPackets(w, 25);
        w.close();
    }

    xicap::Reader r(tmp.path);
    CHECK(readAllOwned(r).size() == 25);
}

TEST_CASE("a capture written without a dictionary still reads", "[dict]")
{
    TempCapture tmp;
    {
        xicap::FramePolicy pol{};
        pol.dictionary = {};
        xicap::Writer w(tmp.path, baseConfig(), pol);
        writeNPackets(w, 25);
        w.close();
    }

    xicap::Reader r(tmp.path);
    CHECK(readAllOwned(r).size() == 25);
}

TEST_CASE("a packet too large for PacketEntry::length is rejected", "[validation]")
{
    TempCapture   tmp;
    xicap::Writer w(tmp.path, baseConfig());

    const std::vector<std::byte> oversized(UINT16_MAX + 1);
    try
    {
        w.write(1'700'000'000'000ULL, xicap::PacketDirection::ServerToClient, oversized);
        FAIL("expected throw");
    }
    catch (const xicap::Error& e)
    {
        CHECK(e.code() == xicap::ErrorCode::PacketTooLarge);
    }
    CHECK(w.packetsWritten() == 0);
}

TEST_CASE("a frame claiming more content than its entries allow is rejected", "[validation]")
{
    TempCapture tmp;
    {
        xicap::Writer w(tmp.path, baseConfig());
        writeNPackets(w, 10);
        w.close();
    }

    // packetCount 0 means no entry can account for the decompressed payload, so
    // the reader must refuse to size a buffer from the zstd content-size field.
    patchFrameHeader(tmp.path, firstFrameOffset(tmp.path), [](xicap::FrameHeader& fh)
                     {
                         fh.packetCount = 0;
                     });

    xicap::Reader     r(tmp.path);
    xicap::ReadPacket pkt;
    try
    {
        r.next(pkt);
        FAIL("expected throw");
    }
    catch (const xicap::Error& e)
    {
        CHECK(e.code() == xicap::ErrorCode::CorruptFrame);
    }
}

TEST_CASE("a pre-2.1 capture with no embedded dictionary falls back to the build's", "[dict]")
{
    TempCapture tmp;
    {
        xicap::Writer w(tmp.path, baseConfig());
        writeNPackets(w, 25);
        w.close();
    }

    // Rewrite the capture without its EXT_ZSTD_DICT block — what a 2.0 writer,
    // which only recorded a dictionary id, produced.
    std::vector<uint8_t> raw;
    {
        std::ifstream f(tmp.path, std::ios::binary);
        raw.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    }

    xicap::Header h{};
    std::memcpy(&h, raw.data(), sizeof(h));
    REQUIRE(h.extensionCount == 1);

    xicap::ExtensionBlockHeader eh{};
    std::memcpy(&eh, raw.data() + sizeof(h), sizeof(eh));
    REQUIRE(eh.type == xicap::EXT_ZSTD_DICT);

    h.extensionCount = 0;
    h.versionMinor   = 0;
    std::memcpy(raw.data(), &h, sizeof(h));
    raw.erase(raw.begin() + sizeof(h), raw.begin() + sizeof(h) + sizeof(eh) + eh.length);

    // The footer's recorded frame offsets shift with the removed block, so this
    // stands in for a truncated 2.0 capture: the reader rebuilds by scanning.
    raw.resize(raw.size() - sizeof(xicap::FooterTrailer));

    TempCapture legacy;
    {
        std::ofstream f(legacy.path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
    }

    xicap::Reader r(legacy.path);
    CHECK(r.versionMinor() == 0);
    CHECK(r.extensions().empty());
    CHECK(readAllOwned(r).size() == 25);
}
