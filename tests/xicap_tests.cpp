#include <xicap/xicap.h>

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
    CHECK(r.endZoneId() == 0); // no LOGIN_ZONE packet was sent
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
    std::fstream f(tmp.path, std::ios::binary | std::ios::in | std::ios::out);
    // First frame begins right after Header + extensions (no extensions in this test).
    f.seekp(sizeof(xicap::Header) + sizeof(xicap::FrameHeader) + 4);
    char b = 0;
    f.read(&b, 1);
    f.seekp(sizeof(xicap::Header) + sizeof(xicap::FrameHeader) + 4);
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
        std::fstream f(tmp.path, std::ios::binary | std::ios::in | std::ios::out);
        f.seekg(0, std::ios::end);
        const auto size = f.tellg();
        REQUIRE(size > sizeof(xicap::Header) + sizeof(xicap::FrameHeader) + 4);
        // Read first frame's compressedSize.
        f.seekg(sizeof(xicap::Header));
        xicap::FrameHeader fh{};
        f.read(reinterpret_cast<char*>(&fh), sizeof(fh));
        // Position of CRC = after frame header + compressed payload.
        const auto crcPos = static_cast<std::streampos>(sizeof(xicap::Header) + sizeof(xicap::FrameHeader) + fh.compressedSize);
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
