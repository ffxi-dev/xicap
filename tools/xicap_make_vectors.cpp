// Writes the conformance set: each tests/vectors/<name>.xicap with
// <name>.json, its expected reading (see vectors.h). Every file is checked
// against what it was built to show before its reading is saved.
//
//   xicap_make_vectors tests/vectors

#include "craft.h"
#include "vectors.h"

#include <xicap/xicap.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;
using namespace xicap;
using namespace craft;

namespace
{

constexpr uint64_t T0 = 1'790'000'000'000ULL;

auto expect(bool ok, const std::string& what) -> void
{
    if (!ok)
    {
        throw std::runtime_error("vector check failed: " + what);
    }
}

auto config() -> WriterConfig
{
    WriterConfig cfg{};
    cfg.clientVersion         = "vectors-1.0";
    cfg.captureAgent          = "xicap_make_vectors";
    cfg.character.contentId   = 0x01020304;
    cfg.character.characterId = 0x0A0B0C0D;
    cfg.character.worldId     = 42;
    std::memcpy(cfg.character.characterName.data(), "Nouurs", 6);
    std::memcpy(cfg.character.worldName.data(), "Asura", 5);
    cfg.network = Network::Retail;
    cfg.captureId.fill(0x33);
    cfg.signingSeed.fill(0x44);
    return cfg;
}

auto policy(bool dictionary) -> FramePolicy
{
    FramePolicy p{};
    p.checkpointIntervalMs = 2000;
    if (!dictionary)
    {
        p.dictionary = {};
    }
    return p;
}

auto game(uint16_t opcode, size_t size, uint8_t fill) -> std::vector<std::byte>
{
    std::vector<std::byte> p(size, std::byte{ fill });
    const auto             hdr = static_cast<uint16_t>((((size / 4) & 0x7F) << 9) | (opcode & 0x1FF));
    p[0]                       = std::byte(hdr & 0xFF);
    p[1]                       = std::byte(hdr >> 8);
    p[2]                       = std::byte{ 0x01 };
    p[3]                       = std::byte{ 0x00 };
    return p;
}

// A zone-in naming the vectors' character, or another one.
auto zoneIn(uint8_t zone, const char* name = "Nouurs", uint32_t id = 0x0A0B0C0D) -> std::vector<std::byte>
{
    auto p                              = game(FFXIPacket::LOGIN_ZONE, 160, 0);
    p[FFXIPacket::LOGIN_ZONE_NO_OFFSET] = std::byte{ zone };
    std::memcpy(p.data() + FFXIPacket::LOGIN_UNIQUE_NO_OFFSET, &id, sizeof(id));
    std::memcpy(p.data() + FFXIPacket::LOGIN_NAME_OFFSET, name, std::strlen(name));
    return p;
}

// `frames` frames of three packets, one second apart, closed.
auto session(const fs::path& path, int frames, bool dictionary, bool close = true) -> void
{
    Writer w(path, config(), policy(dictionary));
    for (int f = 0; f < frames; ++f)
    {
        for (int i = 0; i < 3; ++i)
        {
            w.write(T0 + static_cast<uint64_t>(f) * 1000 + static_cast<uint64_t>(i),
                    i % 2 ? PacketDirection::ClientToServer : PacketDirection::ServerToClient,
                    game(static_cast<uint16_t>(0x100 + f), 16, static_cast<uint8_t>(f)));
        }
        w.flush();
    }
    if (close)
    {
        w.close();
    }
}

auto packetFrames(std::span<const uint8_t> bytes) -> std::vector<FrameRef>
{
    std::vector<FrameRef> out;
    for (const auto& f : framesOf(bytes))
    {
        if (f.header.kind == FrameKind::Packets)
        {
            out.push_back(f);
        }
    }
    return out;
}

auto rawFrame(FrameKind kind, const std::vector<uint8_t>& payload) -> std::vector<uint8_t>
{
    return frameBytes({ .magic = FRAME_MAGIC, .kind = kind, .reserved0 = 0, .markerCount = 0, .payloadSize = static_cast<uint32_t>(payload.size()), .packetCount = 0, .baseTimestamp = T0, .zoneId = 0, .reserved1 = 0 }, payload);
}

auto splice(const std::vector<uint8_t>& bytes, size_t at, size_t remove, const std::vector<uint8_t>& insert) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(at));
    out.insert(out.end(), insert.begin(), insert.end());
    out.insert(out.end(), bytes.begin() + static_cast<std::ptrdiff_t>(at + remove), bytes.end());
    return out;
}

auto count(const fs::path& path, ReaderOptions options = {}) -> uint64_t
{
    Reader     r(path, options);
    ReadPacket p{};
    uint64_t   n = 0;
    while (r.next(p))
    {
        n++;
    }
    return n;
}

auto refuses(const fs::path& path, ErrorCode code) -> bool
{
    try
    {
        count(path);
        return false;
    }
    catch (const Error& e)
    {
        return e.code() == code;
    }
}

} // namespace

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "usage: " << argv[0] << " <output dir>\n";
        return 1;
    }
    const fs::path dir = argv[1];
    fs::create_directories(dir);
    const fs::path tmp = dir / "work.tmp";

    std::vector<std::pair<std::string, std::function<void(const fs::path&)>>> cases = {
        { "clean", [](const fs::path& p)
          {
              auto cfg           = config();
              cfg.policy.name    = "vectors";
              cfg.policy.version = 2;
              cfg.policy.rules.push_back({ .channel = 0, .direction = ExclusionDirection::Both, .action = ExclusionAction::ZeroRange, .opcode = 0x020, .ranges = { { 8, 4 }, { 30, 0xFFFFFFFF } } });
              Writer                       w(p, cfg, policy(true));
              const std::vector<std::byte> hello{ std::byte{ 'h' }, std::byte{ 'i' } };
              w.addExtension(0x8000, hello);
              w.mark(MarkerKind::Login, "start");
              const auto zone = zoneIn(230);
              w.write(T0, PacketDirection::ServerToClient, zone);
              w.write({ .timestamp = T0 + 1, .direction = PacketDirection::ClientToServer, .data = game(0x015, 32, 7), .provenance = PacketFlag::Injected | PacketFlag::FirstInChunk });
              w.write(T0 + 2, PacketDirection::ServerToClient, game(0x017, 64, 'x'));  // chat: stubbed
              w.write(T0 + 3, PacketDirection::ServerToClient, game(0x020, 40, 0xFF)); // redacted
              const std::vector<std::byte> search(24, std::byte{ 0x5A });
              w.write({ .timestamp = T0 + 4, .direction = PacketDirection::ServerToClient, .data = search, .channel = 1, .opcode = 5 });
              const std::vector<std::byte> other(8, std::byte{ 0x0F });
              w.write({ .timestamp = T0 + 5, .direction = PacketDirection::ClientToServer, .data = other, .channel = 9, .opcode = 1 });
              w.write(T0 + 3, PacketDirection::ServerToClient, game(0x0DF, 16, 1)); // clock stepped back: clamped
              for (int f = 1; f <= 4; ++f)
              {
                  for (int i = 0; i < 3; ++i)
                  {
                      w.write(T0 + static_cast<uint64_t>(f) * 1000 + static_cast<uint64_t>(i), PacketDirection::ServerToClient, game(0x0DF, 16, static_cast<uint8_t>(f)));
                  }
                  w.flush();
              }
              w.flush(); // idle: signs
              w.mark(MarkerKind::Note, "between");
              w.write(T0 + 6000, PacketDirection::ServerToClient, game(0x0DF, 16, 9));
              w.mark(MarkerKind::Logout);
              w.mark(MarkerKind::Login);
              w.write(T0 + 9000, PacketDirection::ServerToClient, zone);
              w.close();
              Reader r(p);
              expect(r.complete() && r.verify().signedToEnd, "clean is complete and signed");
              expect(count(p) == 21, "clean holds 21 packets");
              Reader     all(p);
              ReadPacket pk{};
              while (all.next(pk))
              {
              }
              expect(!all.characterMismatch(), "clean's zone-ins name its character");
          } },
        { "character-mismatch", [](const fs::path& p)
          {
              Writer w(p, config(), policy(true));
              w.write(T0, PacketDirection::ServerToClient, zoneIn(230));
              w.write(T0 + 1000, PacketDirection::ServerToClient, zoneIn(231, "Someoneelse", 0x00ABCDEF));
              w.close();
              Reader     r(p);
              ReadPacket pk{};
              while (r.next(pk))
              {
              }
              expect(r.characterMismatch(), "a zone-in naming another character is reported");
          } },
        { "empty", [](const fs::path& p)
          {
              Writer(p, config(), policy(true)).close();
              expect(count(p) == 0 && Reader(p).complete(), "empty is complete with no packets");
          } },
        { "converted", [](const fs::path& p)
          {
              auto cfg                   = config();
              cfg.origin                 = Origin::Converted;
              cfg.clockSource            = ClockSource::Converted;
              cfg.network                = Network::Private;
              cfg.startContext           = StartContext::Unknown;
              cfg.previousCaptureId      = CaptureId{ 0x55, 0x55 };
              const std::string manifest = "{ Captain = { Version = \"1.13.0\" }, FFXI = { IsRetail = false }, StartTime = 1790000000 }";
              cfg.source                 = SourceInfo{ .format = "captain", .formatVersion = "1.13.0", .skippedRecords = 3, .utcOffsetSeconds = -21600, .sourceHash = {}, .metadata = { manifest.begin(), manifest.end() } };
              cfg.source->sourceHash.fill(0xAA);
              Writer w(p, cfg, policy(false));
              for (int i = 0; i < 4; ++i)
              {
                  w.write(T0 + static_cast<uint64_t>(i) * 10, PacketDirection::ServerToClient, game(0x0DF, 16, static_cast<uint8_t>(i)));
              }
              w.close();
              expect(Reader(p).source().has_value(), "converted carries its source");
          } },
        { "cut-off", [&](const fs::path& p)
          {
              session(tmp, 4, true);
              auto       bytes = bytesOf(tmp);
              const auto last  = packetFrames(bytes).back();
              bytes.resize(last.offset + 10);
              save(p, bytes);
              Reader r(p);
              expect(!r.complete() && count(p) == 9 && r.unreadBytes() == 10, "cut-off ends at its last intact frame");
          } },
        { "torn-tail", [&](const fs::path& p)
          {
              session(tmp, 4, true);
              auto bytes = bytesOf(tmp);
              bytes.resize(footerOffset(bytes));
              bytes.resize(bytes.size() + 4096, 0);
              save(p, bytes);
              expect(count(p) == 12 && Reader(p).unreadBytes() == 4096, "a zeroed tail is unread");
          } },
        { "damaged-footer", [&](const fs::path& p)
          {
              session(tmp, 3, true);
              auto bytes = bytesOf(tmp);
              bytes[bytes.size() - 20] ^= 1;
              save(p, bytes);
              Reader r(p);
              expect(!r.complete() && r.footerDamaged() && count(p) == 9, "a damaged footer reads as cut off");
          } },
        { "damaged-middle-complete", [&](const fs::path& p)
          {
              session(tmp, 3, true);
              auto bytes = bytesOf(tmp);
              bytes[packetFrames(bytes)[1].offset + 8] ^= 0x40;
              save(p, bytes);
              expect(refuses(p, ErrorCode::CorruptFrame), "a complete file with a bad frame is refused");
              expect(count(p, { .recovery = true }) == 6, "recovery skips the bad frame");
          } },
        { "damaged-middle-cut-off", [&](const fs::path& p)
          {
              session(tmp, 3, true);
              auto bytes = bytesOf(tmp);
              bytes[packetFrames(bytes)[1].offset + 8] ^= 0x40;
              bytes.resize(footerOffset(bytes));
              save(p, bytes);
              expect(count(p) == 3, "a cut-off capture ends at its bad frame");
              expect(count(p, { .recovery = true }) == 6, "recovery skips the bad frame");
          } },
        { "unknown-skippable-kind", [&](const fs::path& p)
          {
              session(tmp, 2, true);
              auto bytes = bytesOf(tmp);
              bytes.resize(footerOffset(bytes));
              save(p, splice(bytes, packetFrames(bytes)[1].offset, 0, rawFrame(static_cast<FrameKind>(0x02), { 1, 2, 3 })));
              expect(count(p) == 6, "an unknown skippable frame is skipped");
          } },
        { "unknown-required-kind", [&](const fs::path& p)
          {
              session(tmp, 2, true);
              auto bytes = bytesOf(tmp);
              bytes.resize(footerOffset(bytes));
              save(p, splice(bytes, packetFrames(bytes)[1].offset, 0, rawFrame(static_cast<FrameKind>(0x81), { 1, 2, 3 })));
              expect(refuses(p, ErrorCode::UnknownFrameKind), "an unknown must-understand frame is refused");
          } },
        { "unknown-required-flag", [&](const fs::path& p)
          {
              session(tmp, 2, false);
              auto bytes = bytesOf(tmp);
              bytes.resize(footerOffset(bytes));
              const auto f      = packetFrames(bytes)[0];
              const auto edited = rewriteFrame(bytes, f, [](std::vector<uint8_t>& content)
                                               {
                                                   auto e = podAt<PacketEntry>(content, 0);
                                                   e.flags |= 0x0400;
                                                   std::memcpy(content.data(), &e, sizeof(e));
                                               });
              save(p, splice(bytes, f.offset, f.size, edited));
              expect(refuses(p, ErrorCode::UnknownPacketFlag), "an unknown must-understand flag is refused");
          } },
        { "missing-dictionary", [&](const fs::path& p)
          {
              session(tmp, 1, true);
              auto       bytes  = bytesOf(tmp);
              const auto length = podAt<ExtensionBlockHeader>(bytes, HEADER_SIZE).length;
              bytes             = splice(bytes, HEADER_SIZE, 8 + length + 4, {});
              auto header       = podAt<Header>(bytes, 0);
              header.extensionCount--;
              header.headerCrc = internal::crc32({ reinterpret_cast<const uint8_t*>(&header), offsetof(Header, headerCrc) });
              std::memcpy(bytes.data(), &header, sizeof(header));
              save(p, bytes);
              expect(refuses(p, ErrorCode::MissingDictionary), "a file without its dictionary is refused");
          } },
        { "bad-header-crc", [&](const fs::path& p)
          {
              session(tmp, 1, true);
              auto bytes = bytesOf(tmp);
              bytes[120] ^= 1;
              save(p, bytes);
              expect(refuses(p, ErrorCode::HeaderChecksumMismatch), "a damaged header is refused");
          } },
        { "bad-extension-crc", [&](const fs::path& p)
          {
              session(tmp, 1, true);
              auto bytes = bytesOf(tmp);
              bytes[HEADER_SIZE + 100] ^= 1;
              save(p, bytes);
              expect(refuses(p, ErrorCode::ExtensionChecksumMismatch), "a damaged extension is refused");
          } },
        { "format-2", [](const fs::path& p)
          {
              std::vector<uint8_t> old(512);
              std::memcpy(old.data(), "XCAP\x02\x01", 6);
              save(p, old);
              expect(refuses(p, ErrorCode::BadMagic), "a 2.x file is refused");
          } },
        { "edited-packet", [&](const fs::path& p)
          {
              session(tmp, 6, false);
              auto bytes = bytesOf(tmp);
              bytes.resize(footerOffset(bytes));
              // Edit the last packet frame, after at least one checkpoint.
              const auto f      = packetFrames(bytes).back();
              const auto edited = rewriteFrame(bytes, f, [](std::vector<uint8_t>& content)
                                               {
                                                   content[sizeof(PacketEntry) + 6] ^= 0xFF;
                                               });
              save(p, splice(bytes, f.offset, f.size, edited));
              Reader     r(p);
              const auto v = r.verify();
              expect(count(p) == 18 && !v.signedToEnd && v.goodCheckpoints > 0 && v.verifiedPackets < 18, "an edited packet reads but fails after the last good checkpoint");
          } },
    };

    for (const auto& [name, make] : cases)
    {
        const auto path = dir / (name + ".xicap");
        make(path);
        std::ofstream(dir / (name + ".json"), std::ios::binary | std::ios::trunc) << vectors::reading(path);
        std::cout << name << "\n";
    }
    fs::remove(tmp);
    return 0;
}
