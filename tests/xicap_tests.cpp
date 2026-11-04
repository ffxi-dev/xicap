#include "helpers.h"
#include "internal/access.h"
#include "internal/columns.h"
#include "internal/crc32.h"
#include "internal/signing.h"
#include "search.h"
#include "vectors.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

using namespace test;
using namespace craft;

namespace
{

// The packets of a frame, as records over their own bytes.
struct Records
{
    std::vector<Owned>            packets;
    std::vector<internal::Record> records;
};

auto recordsOf(std::vector<Owned> packets, size_t count) -> Records
{
    packets.resize(count);
    Records out{ std::move(packets), {} };
    for (const auto& p : out.packets)
    {
        out.records.push_back({ .timestamp = p.timestamp, .flags = p.flags, .channel = p.channel, .opcode = p.opcode, .data = p.data });
    }
    return out;
}

// Frame `frame` of a cut-off copy, rewritten to hold `records` in its place.
auto replaceFrame(const std::vector<uint8_t>& bytes, const FrameRef& frame, std::span<const internal::Record> records) -> std::vector<uint8_t>
{
    const auto plain  = internal::encodeColumns(records, {});
    const auto header = podAt<FrameHeader>(bytes, frame.offset);
    const auto edited = packetFrame({ .magic = 0, .kind = FrameKind::Packets, .frameFlags = 0, .markerCount = 0, .payloadSize = 0, .packetCount = static_cast<uint32_t>(records.size()), .baseTimestamp = header.baseTimestamp, .zoneId = header.zoneId, .reserved = 0, .plainSize = 0 }, plain);
    return splice(bytes, frame.offset, frame.size, edited);
}

} // namespace

TEST_CASE("round trip keeps header, packets, channels, flags, and markers")
{
    TempCapture tmp;
    CaptureId   firstId{};
    {
        Writer w(tmp.path, config());
        firstId = w.captureId();
        w.mark(MarkerKind::Login, "hello");
        w.write(T0, PacketDirection::ServerToClient, gamePacket(0x0DF, 20));
        w.write({ .timestamp = T0 + 5, .direction = PacketDirection::ClientToServer, .data = gamePacket(0x015, 32), .provenance = PacketFlag::Injected | PacketFlag::FirstInChunk });
        const std::vector<std::byte> search(40, std::byte{ 0x11 });
        w.write({ .timestamp = T0 + 9, .direction = PacketDirection::ClientToServer, .data = search, .channel = 1, .opcode = 0x05 });
        w.close();
    }
    Reader r(tmp.path);
    CHECK(r.versionMajor() == 4);
    CHECK(r.complete());
    CHECK(r.captureId() == firstId);
    CHECK(r.startTimestamp() == T0);
    CHECK(r.endTimestamp() == T0 + 9);
    CHECK(r.totalPacketCount() == 3);
    CHECK(r.clientVersion() == "test-client");
    CHECK(r.character().contentId == 0x01020304);
    CHECK(r.character().characterId == 0x0A0B0C0D);
    CHECK(std::string(r.character().characterName.data()) == "Nouurs");
    CHECK(r.network() == Network::Retail);
    CHECK(r.startContext() == StartContext::Login);
    CHECK(r.policy().name == "xicap-default");

    const auto packets = readAll(r);
    REQUIRE(packets.size() == 3);
    CHECK(packets[0].opcode == 0x0DF);
    REQUIRE(packets[0].markers.size() == 1);
    CHECK(packets[0].markers[0].kind == MarkerKind::Login);
    CHECK(packets[0].markers[0].text == "hello");
    CHECK(packets[1].direction == PacketDirection::ClientToServer);
    CHECK(packets[1].flags == (PacketFlag::ClientToServer | PacketFlag::Injected | PacketFlag::FirstInChunk));
    CHECK(packets[2].channel == 1);
    CHECK(packets[2].opcode == 0x05);
    CHECK(packets[2].data.size() == 40);
}

TEST_CASE("recorded search messages round-trip on channel 1 between game packets")
{
    TempCapture tmp;
    {
        Writer w(tmp.path, config());
        for (const auto& m : search::recorded)
        {
            w.write(T0 + m.offsetMs, PacketDirection::ServerToClient, gamePacket(0x0DF, 20));
            const auto data = m.bytes();
            w.write({ .timestamp = T0 + m.offsetMs, .direction = m.direction, .data = data, .channel = 1, .opcode = std::to_integer<uint16_t>(data[0x0B]) });
        }
        w.write(T0 + 1000, PacketDirection::ServerToClient, gamePacket(0x0DF, 20));
        w.close();
    }
    const auto packets = readAll(tmp.path);
    REQUIRE(packets.size() == std::size(search::recorded) * 2 + 1);
    const uint16_t opcodes[] = { 0x15, 0x95, 0x10, 0x95 };
    for (size_t i = 0; i < std::size(search::recorded); ++i)
    {
        const auto& m    = search::recorded[i];
        const auto& game = packets[i * 2];
        const auto& sent = packets[i * 2 + 1];
        CHECK(game.channel == 0);
        CHECK(game.timestamp == T0 + m.offsetMs);
        CHECK(sent.channel == 1);
        CHECK(sent.opcode == opcodes[i]);
        CHECK(sent.direction == m.direction);
        CHECK(sent.timestamp == T0 + m.offsetMs);
        const auto want = m.bytes();
        REQUIRE(sent.data.size() == want.size());
        CHECK(std::memcmp(sent.data.data(), want.data(), want.size()) == 0);
    }
    CHECK(packets.back().channel == 0);
}

TEST_CASE("two writers pick different capture ids")
{
    TempCapture a;
    TempCapture b;
    Writer      wa(a.path, config());
    Writer      wb(b.path, config());
    CHECK(wa.captureId() != wb.captureId());
}

TEST_CASE("a continued capture names its predecessor")
{
    TempCapture tmp;
    auto        cfg       = config();
    cfg.previousCaptureId = CaptureId{ 1, 2, 3 };
    cfg.startContext      = StartContext::MidSession;
    Writer(tmp.path, cfg).close();
    Reader r(tmp.path);
    CHECK(r.previousCaptureId() == CaptureId{ 1, 2, 3 });
    CHECK(r.startContext() == StartContext::MidSession);
}

TEST_CASE("a recording file only grows")
{
    TempCapture                       tmp;
    std::vector<std::vector<uint8_t>> copies;
    {
        Writer w(tmp.path, config());
        for (int f = 0; f < 4; ++f)
        {
            w.write(T0 + static_cast<uint64_t>(f) * 1000, PacketDirection::ServerToClient, gamePacket(0x010, 24));
            w.flush();
            copies.push_back(bytesOf(tmp.path));
        }
        w.close();
    }
    copies.push_back(bytesOf(tmp.path));
    for (size_t i = 1; i < copies.size(); ++i)
    {
        REQUIRE(copies[i].size() >= copies[i - 1].size());
        CHECK(std::equal(copies[i - 1].begin(), copies[i - 1].end(), copies[i].begin()));
    }
}

TEST_CASE("an empty capture still gets a footer")
{
    TempCapture tmp;
    Writer(tmp.path, config()).close();
    Reader r(tmp.path);
    CHECK(r.complete());
    CHECK(r.totalPacketCount() == 0);
    CHECK(r.startTimestamp() == 0);
    CHECK(readAll(r).empty());
    CHECK(r.verify().signedToEnd);
}

TEST_CASE("timestamps never go backwards and ties stay ties")
{
    TempCapture tmp;
    {
        Writer w(tmp.path, config());
        w.write(T0 + 5000, PacketDirection::ServerToClient, gamePacket(0x010, 8));
        w.write(T0 + 3000, PacketDirection::ServerToClient, gamePacket(0x010, 8)); // clock stepped back
        w.write(T0 + 5000, PacketDirection::ServerToClient, gamePacket(0x010, 8));
        w.write(T0 + 5000, PacketDirection::ServerToClient, gamePacket(0x010, 8));
        w.close();
    }
    for (const auto& p : readAll(tmp.path))
    {
        CHECK(p.timestamp == T0 + 5000);
    }
}

TEST_CASE("a zone-in starts a frame carrying the new zone")
{
    TempCapture tmp;
    {
        Writer w(tmp.path, config());
        w.write(T0, PacketDirection::ServerToClient, gamePacket(0x010, 8));
        w.write(T0 + 1, PacketDirection::ServerToClient, zoneIn(230));
        w.write(T0 + 2, PacketDirection::ServerToClient, gamePacket(0x010, 8));
        w.close();
    }
    Reader r(tmp.path);
    REQUIRE(r.totalFrames() == 2);
    const auto zones = r.listZones();
    REQUIRE(zones.size() == 1);
    CHECK(zones[0].zoneId == 230);
    CHECK(zones[0].timestamp == T0 + 1);
    CHECK(r.seekToZone(230) == SeekResult::Ok);
    ReadPacket p{};
    REQUIRE(r.next(p));
    CHECK(p.opcode == FFXIPacket::LOGIN_ZONE);
}

TEST_CASE("zone-ins are checked against the header's character")
{
    TempCapture tmp;
    const auto  mismatch = [&](const std::vector<std::byte>& zone)
    {
        {
            Writer w(tmp.path, config());
            w.write(T0, PacketDirection::ServerToClient, zoneIn(230));
            w.write(T0 + 1, PacketDirection::ServerToClient, zone);
            w.close();
        }
        Reader r(tmp.path);
        readAll(r);
        return r.characterMismatch();
    };
    CHECK_FALSE(mismatch(zoneIn(231)));
    CHECK(mismatch(zoneIn(231, "Mule")));
    CHECK(mismatch(zoneIn(231, "Nouurs", 0x00000001)));
}

TEST_CASE("chat text is zeroed before it reaches disk, and the packet keeps its layout")
{
    TempCapture       tmp;
    const std::string secret = "meet me at the docks";
    auto              chat   = gamePacket(0x017, 64, 0x11);
    std::memcpy(chat.data() + 0x17, secret.data(), secret.size());
    {
        Writer w(tmp.path, config());
        w.write(T0, PacketDirection::ServerToClient, chat);
        w.close();
    }
    const auto bytes = bytesOf(tmp.path);
    CHECK(std::search(bytes.begin(), bytes.end(), secret.begin(), secret.end()) == bytes.end());
    const auto packets = readAll(tmp.path);
    REQUIRE(packets.size() == 1);
    CHECK((packets[0].flags & PacketFlag::Redacted) != 0);
    CHECK((packets[0].flags & PacketFlag::Excluded) == 0);
    REQUIRE(packets[0].data.size() == 64);
    for (size_t i = 0; i < 64; ++i)
    {
        CHECK(packets[0].data[i] == (i < 0x17 ? static_cast<uint8_t>(chat[i]) : 0));
    }
}

TEST_CASE("a writer refuses a policy too large for a reader to take")
{
    TempCapture tmp;
    auto        cfg = config();
    cfg.policy.rules.clear();
    // 33 rules of 65,535 ranges each: every count is in range, but the block is over 16 MiB.
    for (uint16_t i = 0; i < 33; ++i)
    {
        cfg.policy.rules.push_back({ .channel = 0, .direction = ExclusionDirection::Both, .action = ExclusionAction::ZeroRange, .opcode = i, .ranges = std::vector<ByteRange>(UINT16_MAX, ByteRange{ 8, 4 }) });
    }
    try
    {
        Writer w(tmp.path, cfg);
        w.close();
        FAIL("the writer took the policy");
    }
    catch (const Error& e)
    {
        CHECK(e.code() == ErrorCode::InvalidPolicy);
    }
}

TEST_CASE("the default policy zeroes the text of every chat packet and no other byte")
{
    TempCapture tmp;
    struct Chat
    {
        uint16_t        opcode;
        PacketDirection direction;
        size_t          from; // the text's first byte
        size_t          to;   // past its last
    };
    const std::vector<Chat> chat{
        { 0x017, PacketDirection::ServerToClient, 0x17, 128 },
        { 0x0B5, PacketDirection::ClientToServer, 0x06, 128 },
        { 0x0B6, PacketDirection::ClientToServer, 0x15, 128 },
        { 0x0B7, PacketDirection::ClientToServer, 0x15, 128 },
        { 0x0CC, PacketDirection::ServerToClient, 0x08, 0x88 },
        { 0x0E2, PacketDirection::ClientToServer, 0x10, 0x90 },
    };
    {
        Writer   w(tmp.path, config());
        uint64_t t = T0;
        for (const auto& c : chat)
        {
            w.write(t++, c.direction, gamePacket(c.opcode, 128, 0x5A));
        }
        w.write(t, PacketDirection::ClientToServer, gamePacket(0x017, 64)); // 0x017 from the client is another packet: kept
        w.write(t, PacketDirection::ClientToServer, gamePacket(0x0E0, 64)); // search comment: public, kept
        w.close();
    }
    const auto packets = readAll(tmp.path);
    REQUIRE(packets.size() == 8);
    const auto sent = gamePacket(0, 128, 0x5A);
    for (size_t i = 0; i < chat.size(); ++i)
    {
        INFO(chat[i].opcode);
        CHECK(packets[i].flags & PacketFlag::Redacted);
        REQUIRE(packets[i].data.size() == 128);
        for (size_t b = 4; b < 128; ++b) // the header holds the opcode
        {
            CHECK(packets[i].data[b] == (b >= chat[i].from && b < chat[i].to ? 0 : static_cast<uint8_t>(sent[b])));
        }
    }
    CHECK(packets[6].data.size() == 64);
    CHECK(packets[7].data.size() == 64);
    CHECK(defaultExclusionPolicy().version == 2);
    CHECK(coversDefault(defaultExclusionPolicy()));
    CHECK_FALSE(coversDefault({ .name = "none", .version = 1, .rules = {} }));
    auto stubs = defaultExclusionPolicy();
    for (auto& rule : stubs.rules)
    {
        rule = { .channel = 0, .direction = rule.direction, .action = ExclusionAction::Stub, .opcode = rule.opcode, .ranges = {} };
    }
    CHECK(coversDefault(stubs));
    stubs.rules.pop_back();
    CHECK_FALSE(coversDefault(stubs));
}

TEST_CASE("redaction zeroes byte ranges and keeps the length")
{
    TempCapture tmp;
    auto        cfg = config();
    cfg.policy      = { .name = "test", .version = 2, .rules = { { .channel = 0, .direction = ExclusionDirection::Both, .action = ExclusionAction::ZeroRange, .opcode = 0x020, .ranges = { { 8, 4 }, { 30, 0xFFFFFFFF } } } } };
    {
        Writer w(tmp.path, cfg);
        w.write(T0, PacketDirection::ServerToClient, gamePacket(0x020, 40, 0xFF));
        w.close();
    }
    Reader r(tmp.path);
    CHECK(r.policy().name == "test");
    CHECK(r.policy().version == 2);
    const auto p = readAll(r).at(0);
    CHECK(p.flags & PacketFlag::Redacted);
    REQUIRE(p.data.size() == 40);
    CHECK(p.data[7] == 0xFF);
    CHECK(p.data[8] == 0);
    CHECK(p.data[11] == 0);
    CHECK(p.data[12] == 0xFF);
    CHECK(p.data[29] == 0xFF);
    CHECK(p.data[39] == 0);
}

TEST_CASE("applyPolicy gives what the writer stores")
{
    TempCapture tmp;
    auto        cfg = config();
    cfg.policy.rules.push_back({ .channel = 0, .direction = ExclusionDirection::Both, .action = ExclusionAction::ZeroRange, .opcode = 0x020, .ranges = { { 8, 4 }, { 100, 4 } } });
    const std::vector<std::byte> search(40, std::byte{ 0x5A });
    const auto                   chat     = gamePacket(0x017, 64);
    const auto                   redacted = gamePacket(0x020, 40, 0xFF);
    const auto                   kept     = gamePacket(0x015, 32);
    const std::vector<OutPacket> sent{
        { .timestamp = T0, .direction = PacketDirection::ServerToClient, .data = chat, .provenance = 0xFFFF },
        { .timestamp = T0 + 1, .direction = PacketDirection::ClientToServer, .data = redacted, .provenance = PacketFlag::Modified },
        { .timestamp = T0 + 2, .direction = PacketDirection::ClientToServer, .data = kept, .opcode = 0x123 },
        { .timestamp = T0 + 3, .direction = PacketDirection::ServerToClient, .data = search, .channel = 1, .opcode = 5 },
    };
    {
        Writer w(tmp.path, cfg);
        for (const auto& packet : sent)
        {
            w.write(packet);
        }
        w.close();
    }
    const auto packets = readAll(tmp.path);
    REQUIRE(packets.size() == sent.size());
    for (size_t i = 0; i < sent.size(); ++i)
    {
        const auto stored = applyPolicy(cfg.policy, sent[i]);
        CHECK(stored.opcode == packets[i].opcode);
        CHECK(stored.flags == packets[i].flags);
        CHECK(std::ranges::equal(stored.data, std::as_bytes(std::span{ packets[i].data })));
    }
    CHECK(packets[0].flags == (PacketFlag::Provenance | PacketFlag::Redacted));
    CHECK(packets[0].data.size() == 64);
    CHECK(packets[0].data[0x17] == 0);
    CHECK(packets[1].flags == (PacketFlag::ClientToServer | PacketFlag::Modified | PacketFlag::Redacted));
    CHECK(packets[1].data[8] == 0);
    CHECK(packets[2].opcode == 0x015);
    CHECK(packets[3].opcode == 5);

    CHECK(ruleFor(cfg.policy, 0, PacketDirection::ServerToClient, 0x017)->action == ExclusionAction::ZeroRange);
    CHECK(ruleFor(cfg.policy, 0, PacketDirection::ClientToServer, 0x017) == nullptr);
    CHECK(ruleFor(cfg.policy, 0, PacketDirection::ClientToServer, 0x020)->action == ExclusionAction::ZeroRange);

    const std::vector<std::byte> tooShort(3);
    CHECK_THROWS_AS(applyPolicy(cfg.policy, { .data = tooShort }), Error);
    CHECK(applyPolicy(cfg.policy, { .data = tooShort, .channel = 1 }).data.size() == 3);
}

TEST_CASE("redaction never reaches the game header, so the reader takes what the writer wrote")
{
    TempCapture tmp;
    save(tmp.path, std::vector<uint8_t>{ 1, 2, 3 });
    auto bad = config();
    bad.policy.rules.insert(bad.policy.rules.begin(), { .channel = 0, .direction = ExclusionDirection::Both, .action = ExclusionAction::ZeroRange, .opcode = 0x017, .ranges = { { 0, 2 } } });
    CHECK_THROWS_AS(Writer(tmp.path, bad), Error);
    CHECK(bytesOf(tmp.path) == std::vector<uint8_t>{ 1, 2, 3 }); // refused before the file was opened
    const auto chat = gamePacket(0x017, 64);
    CHECK_THROWS_AS(applyPolicy(bad.policy, { .direction = PacketDirection::ServerToClient, .data = chat }), Error);

    auto good                   = config();
    good.policy.rules.front()   = bad.policy.rules.front();
    good.policy.rules[0].ranges = { { 4, 0xFFFFFFFF } };
    const std::vector<std::byte> search(8, std::byte{ 0x5A });
    good.policy.rules.push_back({ .channel = 1, .direction = ExclusionDirection::Both, .action = ExclusionAction::ZeroRange, .opcode = 5, .ranges = { { 0, 2 } } });
    {
        Writer w(tmp.path, good);
        w.write(T0, PacketDirection::ServerToClient, chat);
        w.write({ .timestamp = T0 + 1, .direction = PacketDirection::ServerToClient, .data = search, .channel = 1, .opcode = 5 });
        w.close();
    }
    const auto packets = readAll(tmp.path);
    REQUIRE(packets.size() == 2);
    CHECK(packets[0].opcode == 0x017);
    CHECK(packets[0].flags & PacketFlag::Redacted);
    CHECK(std::ranges::equal(std::span{ packets[0].data }.first(4), std::as_bytes(std::span{ chat }.first(4)), [](uint8_t a, std::byte b)
                             {
                                 return a == std::to_integer<uint8_t>(b);
                             }));
    CHECK(std::ranges::all_of(std::span{ packets[0].data }.subspan(4), [](uint8_t b)
                              {
                                  return b == 0;
                              }));
    CHECK(packets[1].data[0] == 0); // other channels have no header to keep
}

TEST_CASE("the writer refuses bad input")
{
    TempCapture tmp;
    SECTION("a stub on a channel without one")
    {
        auto cfg   = config();
        cfg.policy = { .name = "x", .version = 1, .rules = { { .channel = 1, .direction = ExclusionDirection::Both, .action = ExclusionAction::Stub, .opcode = 1, .ranges = {} } } };
        CHECK_THROWS_AS(Writer(tmp.path, cfg), Error);
    }
    SECTION("a converted capture without its source, or a live one with it")
    {
        auto cfg   = config();
        cfg.origin = Origin::Converted;
        CHECK_THROWS_AS(Writer(tmp.path, cfg), Error);
        auto live   = config();
        live.source = SourceInfo{};
        CHECK_THROWS_AS(Writer(tmp.path, live), Error);
    }
    SECTION("extension ids outside the range for other programs")
    {
        Writer                       w(tmp.path, config());
        const std::vector<std::byte> data(4);
        CHECK_THROWS_AS(w.addExtension(0x0001, data), Error);
        CHECK_THROWS_AS(w.addExtension(EXT_EXCLUSION_POLICY, data), Error);
        CHECK_NOTHROW(w.addExtension(0x8000, data));
        w.write(T0, PacketDirection::ServerToClient, gamePacket(0x010, 8));
        CHECK_THROWS_AS(w.addExtension(0x8001, data), Error); // after a packet
    }
    SECTION("a game packet under 4 bytes, and writes after close")
    {
        Writer w(tmp.path, config());
        CHECK_THROWS_AS(w.write(T0, PacketDirection::ServerToClient, std::vector<std::byte>(3)), Error);
        w.close();
        CHECK_THROWS_AS(w.write(T0, PacketDirection::ServerToClient, gamePacket(0x010, 8)), Error);
    }
}

TEST_CASE("a source block round-trips on converted captures")
{
    TempCapture tmp;
    auto        cfg            = config();
    cfg.origin                 = Origin::Converted;
    cfg.clockSource            = ClockSource::Converted;
    cfg.network                = Network::Private;
    const std::string manifest = "{ Captain = { Version = \"1.13.0\" }, FFXI = { IsRetail = false } }";
    cfg.source                 = SourceInfo{ .format = "captain", .formatVersion = "1.13.0", .skippedRecords = 1, .utcOffsetSeconds = 21600, .sourceHash = {}, .metadata = { manifest.begin(), manifest.end() } };
    Writer(tmp.path, cfg).close();
    Reader r(tmp.path);
    REQUIRE(r.source());
    CHECK(r.source()->format == "captain");
    CHECK(r.source()->skippedRecords == 1);
    CHECK(r.source()->utcOffsetSeconds == 21600);
    CHECK(std::string(r.source()->metadata.begin(), r.source()->metadata.end()) == manifest);
    CHECK(r.origin() == Origin::Converted);
    CHECK(r.network() == Network::Private);
}

TEST_CASE("a packet over 64 KiB on a non-game channel")
{
    TempCapture                  tmp;
    const std::vector<std::byte> big(100'000, std::byte{ 3 });
    {
        Writer w(tmp.path, config());
        w.write({ .timestamp = T0, .direction = PacketDirection::ServerToClient, .data = big, .channel = 9, .opcode = 1 });
        w.close();
    }
    const auto p = readAll(tmp.path).at(0);
    CHECK(p.channel == 9); // unknown channels pass through
    CHECK(p.data.size() == big.size());
}

TEST_CASE("readers refuse what they must")
{
    TempCapture tmp;
    writeFrames(tmp.path, 2, 3);
    auto bytes = bytesOf(tmp.path);

    SECTION("a 2.x file")
    {
        std::vector<uint8_t> old(512);
        std::memcpy(old.data(), "XCAP\x02\x01", 6);
        save(tmp.path, old);
        CHECK_THROWS_AS(Reader(tmp.path), Error);
    }
    SECTION("a flipped header bit")
    {
        bytes[120] ^= 1;
        save(tmp.path, bytes);
        try
        {
            Reader r(tmp.path);
            FAIL("opened");
        }
        catch (const Error& e)
        {
            CHECK(e.code() == ErrorCode::HeaderChecksumMismatch);
        }
    }
    SECTION("a flipped extension bit")
    {
        bytes[HEADER_SIZE + 20] ^= 1;
        save(tmp.path, bytes);
        try
        {
            Reader r(tmp.path);
            FAIL("opened");
        }
        catch (const Error& e)
        {
            CHECK(e.code() == ErrorCode::ExtensionChecksumMismatch);
        }
    }
    SECTION("a header naming a dictionary")
    {
        auto header         = podAt<Header>(bytes, 0);
        header.dictionaryId = 0x1234;
        header.headerCrc    = internal::crc32({ reinterpret_cast<const uint8_t*>(&header), offsetof(Header, headerCrc) });
        std::memcpy(bytes.data(), &header, sizeof(header));
        save(tmp.path, bytes);
        try
        {
            Reader r(tmp.path);
            FAIL("opened");
        }
        catch (const Error& e)
        {
            CHECK(e.code() == ErrorCode::DictionaryMismatch);
        }
    }
}

TEST_CASE("frame kinds and flags a reader must understand")
{
    TempCapture tmp;
    writeFrames(tmp.path, 2, 3, alone());
    auto bytes = bytesOf(tmp.path);
    bytes.resize(footerOffset(bytes)); // cut off, so frames can be spliced in
    const auto frames = framesOf(bytes);

    const auto withKind = [&](uint8_t kind)
    {
        const FrameHeader            h{ .magic = FRAME_MAGIC, .kind = static_cast<FrameKind>(kind), .frameFlags = 0, .markerCount = 0, .payloadSize = 3, .packetCount = 0, .baseTimestamp = T0, .zoneId = 0, .reserved = 0, .plainSize = 0 };
        const std::array<uint8_t, 3> payload{ 1, 2, 3 };
        return splice(bytes, frames[1].offset, 0, frameBytes(h, payload));
    };

    SECTION("an unknown skippable kind is skipped")
    {
        save(tmp.path, withKind(0x02));
        CHECK(readAll(tmp.path).size() == 6);
    }
    SECTION("an unknown must-understand kind is refused")
    {
        save(tmp.path, withKind(0x81));
        CHECK_THROWS_AS(Reader(tmp.path), Error);
    }
    SECTION("an unknown must-understand flag is refused")
    {
        auto frame = recordsOf(readAll(tmp.path), 3);
        frame.records[0].flags |= 0x0400;
        save(tmp.path, replaceFrame(bytes, frames[0], frame.records));
        Reader     r(tmp.path);
        ReadPacket p{};
        CHECK_THROWS_AS(r.next(p), Error);
    }
}

TEST_CASE("cut-off captures read up to the last intact frame")
{
    TempCapture tmp;
    writeFrames(tmp.path, 3);
    const auto bytes  = bytesOf(tmp.path);
    const auto frames = framesOf(bytes);

    SECTION("power lost mid-frame")
    {
        truncateAt(tmp.path, frames[2].offset + 10);
        Reader r(tmp.path);
        CHECK_FALSE(r.complete());
        CHECK(readAll(r).size() == 6);
        CHECK(r.unreadBytes() == 10);
    }
    SECTION("a tail torn to zeros")
    {
        auto torn = bytes;
        torn.resize(frames[2].offset);
        torn.resize(torn.size() + 4096, 0);
        save(tmp.path, torn);
        CHECK(readAll(tmp.path).size() == 6);
    }
    SECTION("the footer cut off")
    {
        truncateAt(tmp.path, footerOffset(bytes));
        Reader r(tmp.path);
        CHECK_FALSE(r.complete());
        CHECK_FALSE(r.footerDamaged());
        CHECK(readAll(r).size() == 9);
    }
    SECTION("a damaged footer")
    {
        auto damaged = bytes;
        damaged[damaged.size() - 20] ^= 1;
        save(tmp.path, damaged);
        Reader r(tmp.path);
        CHECK_FALSE(r.complete());
        CHECK(r.footerDamaged());
        CHECK(readAll(r).size() == 9);
    }
}

TEST_CASE("a damaged middle frame")
{
    TempCapture tmp;
    const auto  damage = [&](FramePolicy policy)
    {
        writeFrames(tmp.path, 3, 3, policy);
        auto bytes = bytesOf(tmp.path);
        // Damage the second packet frame's size field.
        bytes[packetFrames(bytes)[1].offset + 8] ^= 0x40;
        return bytes;
    };

    SECTION("with a footer: refused, or skipped in recovery mode")
    {
        save(tmp.path, damage(alone()));
        CHECK_THROWS_AS(readAll(tmp.path), Error);
        CHECK(readAll(tmp.path, { .recovery = true }).size() == 6);
    }
    SECTION("without a footer: the capture ends there, or recovery skips it")
    {
        auto bytes = damage(alone());
        bytes.resize(footerOffset(bytes));
        save(tmp.path, bytes);
        CHECK(readAll(tmp.path).size() == 3);
        Reader r(tmp.path, { .recovery = true });
        CHECK(readAll(r).size() == 6);
        CHECK(r.skippedRegions().size() == 1);
    }
    SECTION("in a stream, recovery loses the frames up to the next restart")
    {
        auto bytes = damage({});
        bytes.resize(footerOffset(bytes));
        save(tmp.path, bytes);
        CHECK(readAll(tmp.path).size() == 3);
        Reader r(tmp.path, { .recovery = true });
        CHECK(readAll(r).size() == 3);
        const auto first = packetFrames(bytes)[0];
        REQUIRE(r.skippedRegions().size() == 1);
        CHECK(r.skippedRegions()[0].offset == first.offset + first.size);
        CHECK(r.skippedRegions()[0].offset + r.skippedRegions()[0].length == bytes.size());
    }
}

TEST_CASE("a game packet whose opcode differs from its header is a bad frame")
{
    TempCapture tmp;
    writeFrames(tmp.path, 1, 3, alone());
    auto bytes = bytesOf(tmp.path);
    bytes.resize(footerOffset(bytes));
    auto frame = recordsOf(readAll(tmp.path), 3);
    frame.records[0].opcode ^= 1;
    save(tmp.path, replaceFrame(bytes, framesOf(bytes).at(0), frame.records));
    CHECK(readAll(tmp.path).empty()); // cut off: ends at the bad frame
}

TEST_CASE("signatures")
{
    TempCapture tmp;
    auto        policy          = alone();
    policy.checkpointIntervalMs = 2000;
    writeFrames(tmp.path, 6, 3, policy);
    auto bytes = bytesOf(tmp.path);

    SECTION("a clean capture is signed to the end")
    {
        Reader     r(tmp.path);
        const auto v = r.verify();
        CHECK(v.signedToEnd);
        CHECK(v.verifiedPackets == 18);
        CHECK(v.key == r.signingKey());
        CHECK(v.goodCheckpoints >= 2);
        CHECK_FALSE(v.firstFailureOffset);
        CHECK_FALSE(v.seal);
    }
    SECTION("a cut-off capture verifies up to its last checkpoint")
    {
        uint64_t packetsBefore = 0;
        uint64_t running       = 0;
        for (const auto& f : framesOf(bytes))
        {
            if (f.info.kind == FrameKind::Checkpoint)
            {
                packetsBefore = running;
            }
            running += f.info.packetCount;
        }
        REQUIRE(packetsBefore != 0);
        truncateAt(tmp.path, footerOffset(bytes));
        Reader     r(tmp.path);
        const auto v = r.verify();
        CHECK_FALSE(v.signedToEnd);
        CHECK(v.verifiedPackets == packetsBefore);
        CHECK(readAll(r).size() == 18);
    }
    // The tampering below changes frame sizes, so it works on cut-off copies,
    // where no footer offsets need to stay valid.
    bytes.resize(footerOffset(bytes));
    const auto frames = framesOf(bytes);

    SECTION("an edited packet still reads but fails verification")
    {
        auto frame = recordsOf(readAll(tmp.path), 3);
        frame.packets[0].data[6] ^= 0xFF;
        save(tmp.path, replaceFrame(bytes, frames[0], frame.records));
        Reader r(tmp.path);
        CHECK(readAll(r).size() == 18);
        const auto v = r.verify();
        CHECK_FALSE(v.signedToEnd);
        CHECK(v.verifiedPackets == 0);
        CHECK(v.firstFailureOffset);
    }
    SECTION("swapped frames run time backwards, so the capture ends at the swap")
    {
        const std::vector<uint8_t> first(bytes.begin() + static_cast<std::ptrdiff_t>(frames[0].offset), bytes.begin() + static_cast<std::ptrdiff_t>(frames[0].offset + frames[0].size));
        auto                       swapped = splice(bytes, frames[0].offset, frames[0].size, {});
        swapped                            = splice(swapped, frames[0].offset + frames[1].size, 0, first);
        save(tmp.path, swapped);
        Reader     r(tmp.path);
        const auto v = r.verify();
        CHECK(readAll(r).size() == 3);
        CHECK(v.verifiedPackets == 0);
    }
}

TEST_CASE("checkpoints follow activity")
{
    TempCapture tmp;
    const auto  checkpoints = [&]
    {
        const auto frames = framesOf(bytesOf(tmp.path));
        return std::ranges::count_if(frames, [](const FrameRef& f)
                                     {
                                         return f.info.kind == FrameKind::Checkpoint;
                                     });
    };

    SECTION("a busy session signs about once a minute")
    {
        Writer w(tmp.path, config());
        for (uint64_t s = 0; s < 600; ++s)
        {
            w.write(T0 + s * 1000, PacketDirection::ServerToClient, gamePacket(0x010, 16));
        }
        w.flush();
        CHECK((checkpoints() >= 9 && checkpoints() <= 10));
        w.close();
    }
    SECTION("an idle flush signs a burst once")
    {
        Writer w(tmp.path, config());
        w.write(T0, PacketDirection::ServerToClient, gamePacket(0x010, 16));
        w.flush(); // ends the frame
        CHECK(checkpoints() == 0);
        w.flush(); // idle: signs it
        CHECK(checkpoints() == 1);
        const auto size = fs::file_size(tmp.path);
        w.flush(); // nothing new
        CHECK(fs::file_size(tmp.path) == size);
        w.close();
    }
    SECTION("login and logout sign what came before, but not an empty start")
    {
        Writer w(tmp.path, config());
        w.mark(MarkerKind::Login);
        CHECK(checkpoints() == 0);
        w.write(T0, PacketDirection::ServerToClient, gamePacket(0x010, 16));
        w.mark(MarkerKind::Logout);
        CHECK(checkpoints() == 1);
        w.mark(MarkerKind::Login);
        CHECK(checkpoints() == 1);
        w.write(T0 + 10'000, PacketDirection::ServerToClient, gamePacket(0x010, 16));
        w.close();
        const auto packets = readAll(tmp.path);
        REQUIRE(packets.size() == 2);
        REQUIRE(packets[0].markers.size() == 1);
        CHECK(packets[0].markers[0].kind == MarkerKind::Login);
        REQUIRE(packets[1].markers.size() == 2);
        CHECK(packets[1].markers[0].kind == MarkerKind::Logout);
        CHECK(packets[1].markers[1].kind == MarkerKind::Login);
    }
}

TEST_CASE("marker text is cut between characters")
{
    TempCapture tmp;
    std::string text(1023, 'a');
    text += "\xC3\xA9"; // é straddles the 1024-byte limit
    {
        Writer w(tmp.path, config());
        w.mark(MarkerKind::Note, text);
        w.write(T0, PacketDirection::ServerToClient, gamePacket(0x010, 8));
        w.close();
    }
    CHECK(readAll(tmp.path).at(0).markers.at(0).text == std::string(1023, 'a'));
}

TEST_CASE("seek to a time")
{
    TempCapture tmp;
    writeFrames(tmp.path, 5);
    Reader r(tmp.path);
    REQUIRE(r.seekToTime(T0 + 2001) == SeekResult::Ok);
    ReadPacket p{};
    REQUIRE(r.next(p));
    CHECK(p.timestamp == T0 + 2001);
    CHECK(r.currentFrameIndex() == 2);
}

TEST_CASE("Ed25519 matches RFC 8032 test 1")
{
    // RFC 8032 section 7.1, TEST 1: empty message.
    SecretSeed                 seedBytes{ 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60 };
    const PublicKey            expected{ 0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a };
    const internal::SigningKey key(seedBytes);
    CHECK(key.publicKey() == expected);

    uint8_t   secret[64];
    PublicKey pub{};
    crypto_ed25519_key_pair(secret, pub.data(), seedBytes.data());
    Signature sig{};
    crypto_ed25519_sign(sig.data(), secret, nullptr, 0);
    const Signature expectedSig{ 0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b };
    CHECK(sig == expectedSig);
}

TEST_CASE("SHA-512 matches FIPS 180-4 for abc")
{
    std::array<uint8_t, 64> hash{};
    crypto_sha512(hash.data(), reinterpret_cast<const uint8_t*>("abc"), 3);
    CHECK(hash[0] == 0xdd);
    CHECK(hash[1] == 0xaf);
    CHECK(hash[63] == 0x9f);
}

TEST_CASE("CRC-32 check value")
{
    CHECK(internal::crc32({ reinterpret_cast<const uint8_t*>("123456789"), 9 }) == 0xCBF43926);
}

#ifdef __linux__
TEST_CASE("write errors are raised")
{
    Writer w("/dev/full", config());
    w.write(T0, PacketDirection::ServerToClient, gamePacket(0x010, 16));
    CHECK_THROWS_AS(w.flush(), Error);
}
#endif

TEST_CASE("the conformance set reads as recorded")
{
    size_t checked = 0;
    for (const auto& entry : fs::directory_iterator(XICAP_VECTORS_DIR))
    {
        if (entry.path().extension() != ".xicap")
        {
            continue;
        }
        auto       expectedPath = entry.path();
        const auto expected     = bytesOf(expectedPath.replace_extension(".json"));
        INFO(entry.path().filename().string());
        CHECK(vectors::reading(entry.path()) == std::string(expected.begin(), expected.end()));
        checked++;
    }
    CHECK(checked >= 28);
}

TEST_CASE("the writer keeps frames within the reader's limits")
{
    TempCapture tmp;
    FramePolicy policy        = {};
    policy.maxPacketsPerFrame = 2'000'000;        // over the 1,048,576 a frame can hold
    policy.maxFrameSize       = 64 * 1024 * 1024; // over the 16 MiB a frame can hold
    policy.maxFrameTimeMs     = 1'000'000;
    {
        Writer w(tmp.path, config(), policy);
        for (int i = 0; i < 70'000; ++i)
        {
            w.write(T0, PacketDirection::ServerToClient, gamePacket(0x010, 8));
        }
        const std::vector<std::byte> big(300'000, std::byte{ 1 });
        for (int i = 0; i < 60; ++i) // 18 MB on one channel
        {
            w.write({ .timestamp = T0, .direction = PacketDirection::ServerToClient, .data = big, .channel = 2, .opcode = 1 });
        }
        w.close();
    }
    Reader r(tmp.path);
    CHECK(readAll(r).size() == 70'060);
    CHECK(r.totalFrames() >= 2);
    for (const auto& f : framesOf(bytesOf(tmp.path)))
    {
        CHECK(f.info.plainSize <= FrameLimits::MAX_CONTENT_SIZE);
    }
}

TEST_CASE("a footer whose offset wraps the size check is not trusted")
{
    TempCapture tmp;
    writeFrames(tmp.path, 2);
    auto bytes   = bytesOf(tmp.path);
    auto trailer = podAt<FooterTrailer>(bytes, bytes.size() - sizeof(FooterTrailer));
    // offset + count * 24 + 112 wraps around to the file size.
    trailer.entryCount  = 0xFFFFFFFF;
    trailer.indexOffset = uint64_t{ bytes.size() } - sizeof(FooterTrailer) - uint64_t{ 0xFFFFFFFF } * sizeof(FooterIndexEntry);
    trailer.trailerCrc  = internal::crc32({ reinterpret_cast<const uint8_t*>(&trailer), offsetof(FooterTrailer, trailerCrc) });
    std::memcpy(bytes.data() + bytes.size() - sizeof(FooterTrailer), &trailer, sizeof(trailer));
    save(tmp.path, bytes);
    Reader r(tmp.path);
    CHECK_FALSE(r.complete());
    CHECK(r.footerDamaged());
    CHECK(readAll(r).size() == 6);
}

TEST_CASE("markers never push a frame past what a reader takes")
{
    TempCapture tmp;
    SECTION("a packet that only fits without the markers before it is refused")
    {
        Writer w(tmp.path, config());
        w.mark(MarkerKind::Note, "x");
        const std::vector<std::byte> big(FrameLimits::MAX_CONTENT_SIZE - 20, std::byte{ 1 });
        CHECK_THROWS_AS(w.write({ .timestamp = T0, .direction = PacketDirection::ServerToClient, .data = big, .channel = 2, .opcode = 1 }), Error);
        Writer alone(tmp.path, config());
        CHECK_NOTHROW(alone.write({ .timestamp = T0, .direction = PacketDirection::ServerToClient, .data = big, .channel = 2, .opcode = 1 }));
    }
    SECTION("at most 65535 markers wait for a packet")
    {
        {
            Writer w(tmp.path, config());
            for (int i = 0; i < 65535; ++i)
            {
                w.mark(MarkerKind::Note);
            }
            CHECK_THROWS_AS(w.mark(MarkerKind::Note), Error);
            w.write(T0, PacketDirection::ServerToClient, gamePacket(0x010, 8));
            w.close();
        }
        CHECK(readAll(tmp.path).at(0).markers.size() == 65535);
    }
}
