// Writes the conformance set: each tests/vectors/4-<name>.xicap with 4-<name>.json, its expected reading (see
// vectors.h). Every file is checked against what it was built to show before its reading is saved. The files are the
// same byte for byte only with the zstd version they were made with (1.5.7).
//
//   xicap_make_vectors tests/vectors

#include "craft.h"
#include "search.h"
#include "vectors.h"

#include "internal/columns.h"
#include "internal/transcode.h"

#include <xicap/xicap.h>

#include <algorithm>
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

// Small frames, streams of a few frames, a checkpoint every two seconds.
auto shortStreams() -> FramePolicy
{
    auto p                 = FramePolicy::live();
    p.maxFrameSize         = 128;
    p.restartBytes         = 400;
    p.checkpointIntervalMs = 2000;
    return p;
}

// Each frame a stream of its own.
auto alone() -> FramePolicy
{
    auto p         = shortStreams();
    p.restartBytes = 0;
    return p;
}

auto game(uint16_t opcode, size_t size, uint8_t fill, uint16_t sync) -> std::vector<std::byte>
{
    std::vector<std::byte> p(size, std::byte{ fill });
    const auto             hdr = static_cast<uint16_t>((((size / 4) & 0x7F) << 9) | (opcode & 0x1FF));
    p[0]                       = std::byte(hdr & 0xFF);
    p[1]                       = std::byte(hdr >> 8);
    p[2]                       = std::byte(sync & 0xFF);
    p[3]                       = std::byte(sync >> 8);
    return p;
}

// A zone-in naming the vectors' character.
auto zoneIn(uint8_t zone, uint16_t sync) -> std::vector<std::byte>
{
    auto           p                    = game(FFXIPacket::LOGIN_ZONE, 160, 0, sync);
    const uint32_t id                   = 0x0A0B0C0D;
    p[FFXIPacket::LOGIN_ZONE_NO_OFFSET] = std::byte{ zone };
    std::memcpy(p.data() + FFXIPacket::LOGIN_UNIQUE_NO_OFFSET, &id, sizeof(id));
    std::memcpy(p.data() + FFXIPacket::LOGIN_NAME_OFFSET, "Nouurs", 6);
    return p;
}

// `frames` frames of three packets, one second apart, with a note before the second packet of each.
auto session(const fs::path& path, int frames, FramePolicy policy, bool close = true) -> void
{
    Writer w(path, config(), policy);
    w.mark(MarkerKind::Login, "in");
    for (int f = 0; f < frames; ++f)
    {
        for (int i = 0; i < 3; ++i)
        {
            if (i == 1)
            {
                w.mark(MarkerKind::Note, "n" + std::to_string(f));
            }
            w.write(T0 + static_cast<uint64_t>(f) * 1000 + static_cast<uint64_t>(i), i % 2 ? PacketDirection::ClientToServer : PacketDirection::ServerToClient, game(static_cast<uint16_t>(0x100 + f % 4), 16, static_cast<uint8_t>(f), static_cast<uint16_t>(f * 3 + i)));
        }
        w.flush();
    }
    if (close)
    {
        w.close();
    }
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

auto cutOff(const fs::path& path) -> std::vector<uint8_t>
{
    auto bytes = bytesOf(path);
    bytes.resize(footerOffset(bytes));
    return bytes;
}

auto mogsafe() -> TranscodeOptions
{
    TranscodeOptions o{ .policy = FramePolicy::archive(), .seed = {}, .agent = "mogsafe vectors" };
    o.seed.fill(0x99);
    return o;
}

auto seal(const fs::path& src, const fs::path& dst) -> void
{
    internal::transcode(src, dst, mogsafe(), { .edit = {}, .check = true, .sealedAt = T0 + 86'400'000 });
}

// FORMAT.md's example plaintext: three 0x0DF packets, syncs 1 to 3.
auto examplePlain() -> std::vector<uint8_t>
{
    return {
        0x00,
        0x0a,
        0x0a,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xdf,
        0x01,
        0xdf,
        0x01,
        0xdf,
        0x01,
        0x00,
        0x00,
        0x00,
        0x02,
        0x02,
        0x02,
        0x30,
        0xdf,
        0x08,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0xdf,
        0x08,
        0x00,
        0x00,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0x01,
        0xdf,
        0x08,
        0x00,
        0x00,
        0x02,
        0x02,
        0x02,
        0x02,
        0x02,
        0x02,
        0x02,
        0x02,
        0x02,
        0x02,
        0x02,
        0x02,
    };
}

// Three frames of their own streams, the middle one replaced by a frame holding `plain` as three packets.
auto badMiddle(const fs::path& tmp, const fs::path& p, const std::vector<uint8_t>& plain) -> void
{
    session(tmp, 3, alone());
    const auto bytes = cutOff(tmp);
    const auto f     = packetFrames(bytes)[1];
    const auto h     = podAt<FrameHeader>(bytes, f.offset);
    save(p, splice(bytes, f.offset, f.size, packetFrame({ .magic = 0, .kind = FrameKind::Packets, .frameFlags = 0, .markerCount = 0, .payloadSize = 0, .packetCount = 3, .baseTimestamp = h.baseTimestamp, .zoneId = 0, .reserved = 0, .plainSize = 0 }, plain)));
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
    const fs::path tmp  = dir / "work.tmp";
    const fs::path tmp2 = dir / "work2.tmp";

    std::vector<std::pair<std::string, std::function<void(const fs::path&)>>> cases = {
        { "example", [](const fs::path& p)
          {
              Writer w(p, config());
              for (int i = 0; i < 3; ++i)
              {
                  w.write(T0 + static_cast<uint64_t>(i) * 10, PacketDirection::ServerToClient, game(0x0DF, 16, static_cast<uint8_t>(i), static_cast<uint16_t>(i + 1)));
              }
              w.close();
              const auto bytes = bytesOf(p);
              expect(plainOf(bytes, packetFrames(bytes).at(0)) == examplePlain(), "the example frame holds FORMAT.md's plaintext");
          } },
        { "clean", [](const fs::path& p)
          {
              auto cfg           = config();
              cfg.policy.name    = "vectors";
              cfg.policy.version = 2;
              cfg.policy.rules.push_back({ .channel = 0, .direction = ExclusionDirection::Both, .action = ExclusionAction::ZeroRange, .opcode = 0x020, .ranges = { { 8, 4 }, { 30, 0xFFFFFFFF } } });
              Writer                       w(p, cfg, shortStreams());
              const std::vector<std::byte> hello{ std::byte{ 'h' }, std::byte{ 'i' } };
              w.addExtension(0x8000, hello);
              w.mark(MarkerKind::Login, "start");
              w.write(T0, PacketDirection::ServerToClient, zoneIn(230, 1));
              w.write({ .timestamp = T0 + 1, .direction = PacketDirection::ClientToServer, .data = game(0x015, 32, 7, 1), .provenance = PacketFlag::Injected | PacketFlag::FirstInChunk });
              w.write(T0 + 2, PacketDirection::ServerToClient, game(0x017, 64, 'x', 2));  // chat: its text zeroed
              w.write(T0 + 3, PacketDirection::ServerToClient, game(0x020, 40, 0xFF, 3)); // redacted
              const std::vector<std::byte> search(24, std::byte{ 0x5A });
              w.write({ .timestamp = T0 + 4, .direction = PacketDirection::ServerToClient, .data = search, .channel = 1, .opcode = 5 });
              const std::vector<std::byte> other(8, std::byte{ 0x0F });
              w.write({ .timestamp = T0 + 5, .direction = PacketDirection::ClientToServer, .data = other, .channel = 9, .opcode = 1 });
              w.write(T0 + 3, PacketDirection::ServerToClient, game(0x0DF, 16, 1, 4)); // clock stepped back: clamped
              for (int f = 1; f <= 4; ++f)
              {
                  for (int i = 0; i < 3; ++i)
                  {
                      w.write(T0 + static_cast<uint64_t>(f) * 1000 + static_cast<uint64_t>(i), PacketDirection::ServerToClient, game(0x0DF, 16, static_cast<uint8_t>(f), static_cast<uint16_t>(4 + f * 3 + i)));
                  }
                  w.flush();
              }
              w.flush(); // idle: signs
              w.mark(MarkerKind::Note, "between");
              w.write(T0 + 6000, PacketDirection::ServerToClient, game(0x0DF, 16, 9, 0xFFFF));
              w.write(T0 + 6001, PacketDirection::ServerToClient, game(0x0DF, 16, 9, 0x0002)); // the sync wraps
              w.mark(MarkerKind::Logout);
              w.mark(MarkerKind::Login);
              w.write(T0 + 9000, PacketDirection::ServerToClient, zoneIn(231, 3));
              w.close();
              Reader r(p);
              expect(r.complete() && r.verify().signedToEnd && r.verify().goodCheckpoints >= 2, "clean is complete, signed, with checkpoints");
              expect(count(p) == 22, "clean holds 22 packets");
          } },
        { "empty", [](const fs::path& p)
          {
              Writer(p, config()).close();
              expect(count(p) == 0 && Reader(p).complete() && Reader(p).verify().signedToEnd, "empty is complete and signed");
          } },
        { "search", [](const fs::path& p)
          {
              Writer   w(p, config());
              uint16_t sync = 0;
              w.write(T0, PacketDirection::ServerToClient, zoneIn(230, sync++));
              for (const auto& m : search::recorded)
              {
                  const auto data = m.bytes();
                  w.write({ .timestamp = T0 + 100 + m.offsetMs, .direction = m.direction, .data = data, .channel = 1, .opcode = std::to_integer<uint16_t>(data[0x0B]) });
                  w.write(T0 + 100 + m.offsetMs, PacketDirection::ServerToClient, game(0x0DF, 16, 1, sync++));
              }
              w.close();
              expect(count(p) == 1 + 2 * std::size(search::recorded), "search holds every recorded message");
          } },
        { "restarts", [](const fs::path& p)
          {
              session(p, 12, shortStreams());
              const auto frames   = packetFrames(bytesOf(p));
              const auto restarts = std::ranges::count_if(frames, [](const FrameRef& f)
                                                          {
                                                              return f.info.restart();
                                                          });
              expect(restarts >= 3 && restarts < static_cast<std::ptrdiff_t>(frames.size()), "restarts has several streams of several frames");
          } },
        { "cut-off", [&](const fs::path& p)
          {
              session(tmp, 6, shortStreams());
              auto       bytes  = cutOff(tmp);
              const auto frames = packetFrames(bytes);
              const auto last   = std::ranges::find_if(frames.rbegin(), frames.rend(), [](const FrameRef& f)
                                                       {
                                                         return !f.info.restart();
                                                       });
              bytes.resize(last->offset + 10);
              save(p, bytes);
              Reader r(p);
              expect(!r.complete() && r.unreadBytes() == 10 && count(p) > 0 && r.verify().verifiedPackets > 0, "cut-off ends mid-stream, after a checkpoint");
          } },
        { "torn-tail", [&](const fs::path& p)
          {
              session(tmp, 4, shortStreams());
              auto bytes = cutOff(tmp);
              bytes.resize(bytes.size() + 4096, 0);
              save(p, bytes);
              expect(count(p) == 12 && Reader(p).unreadBytes() == 4096, "a zeroed tail is unread");
          } },
        { "damaged-footer", [&](const fs::path& p)
          {
              session(tmp, 3, shortStreams());
              auto bytes = bytesOf(tmp);
              bytes[bytes.size() - 20] ^= 1;
              save(p, bytes);
              Reader r(p);
              expect(!r.complete() && r.footerDamaged() && count(p) == 9, "a damaged footer reads as cut off");
          } },
        { "unknown-trailer-flag", [&](const fs::path& p)
          {
              session(tmp, 3, shortStreams());
              auto bytes   = bytesOf(tmp);
              auto trailer = podAt<FooterTrailer>(bytes, bytes.size() - sizeof(FooterTrailer));
              trailer.trailerFlags |= 0x80;
              trailer.trailerCrc = internal::crc32({ reinterpret_cast<const uint8_t*>(&trailer), offsetof(FooterTrailer, trailerCrc) });
              std::memcpy(bytes.data() + bytes.size() - sizeof(trailer), &trailer, sizeof(trailer));
              save(p, bytes);
              Reader r(p);
              expect(!r.complete() && r.footerDamaged() && count(p) == 9, "an unknown trailer flag reads as cut off");
          } },
        { "index-disagrees", [&](const fs::path& p)
          {
              session(tmp, 3, shortStreams());
              auto       bytes   = bytesOf(tmp);
              auto       trailer = podAt<FooterTrailer>(bytes, bytes.size() - sizeof(FooterTrailer));
              auto       entry   = podAt<FooterIndexEntry>(bytes, trailer.indexOffset);
              const auto size    = size_t{ trailer.entryCount } * sizeof(FooterIndexEntry);
              entry.zoneId ^= 1; // the CRCs hold, but the index names another zone than the frame does
              std::memcpy(bytes.data() + trailer.indexOffset, &entry, sizeof(entry));
              trailer.indexCrc   = internal::crc32({ bytes.data() + trailer.indexOffset, size });
              trailer.trailerCrc = internal::crc32({ reinterpret_cast<const uint8_t*>(&trailer), offsetof(FooterTrailer, trailerCrc) });
              std::memcpy(bytes.data() + bytes.size() - sizeof(trailer), &trailer, sizeof(trailer));
              save(p, bytes);
              expect(refuses(p, ErrorCode::CorruptFrame) && count(p, { .recovery = true }) == 9, "an index that disagrees with the frames is refused");
          } },
        { "damaged-stream-complete", [&](const fs::path& p)
          {
              session(tmp, 8, shortStreams());
              auto       bytes  = bytesOf(tmp);
              const auto frames = packetFrames(bytes);
              const auto target = std::ranges::find_if(frames, [](const FrameRef& f)
                                                       {
                                                           return !f.info.restart();
                                                       });
              bytes[target->offset + sizeof(FrameHeader) + 1] ^= 0x40;
              save(p, bytes);
              expect(refuses(p, ErrorCode::CorruptFrame), "a complete file with a bad frame is refused");
              Reader r(p, { .recovery = true });
              expect(count(p, { .recovery = true }) < 24 && count(p, { .recovery = true }) > 3, "recovery resumes at the next restart");
          } },
        { "damaged-stream-cut-off", [&](const fs::path& p)
          {
              session(tmp, 8, shortStreams());
              auto       bytes  = cutOff(tmp);
              const auto frames = packetFrames(bytes);
              const auto target = std::ranges::find_if(frames, [](const FrameRef& f)
                                                       {
                                                           return !f.info.restart();
                                                       });
              bytes[target->offset + sizeof(FrameHeader) + 1] ^= 0x40;
              save(p, bytes);
              expect(count(p) == static_cast<uint64_t>(target - frames.begin()) * 3, "a cut-off file ends at its bad frame");
          } },
        { "bad-plaintext-mid-stream", [&](const fs::path& p)
          {
              session(tmp, 8, shortStreams());
              const auto bytes  = cutOff(tmp);
              const auto frames = packetFrames(bytes);
              // A stream of three frames or more. Its second frame decompresses, but its plaintext breaks a rule; the
              // frames after it in the stream are bad too, so recovery skips to the next restart.
              size_t first = 0;
              while (!(frames[first].info.restart() && !frames[first + 1].info.restart() && !frames[first + 2].info.restart()))
              {
                  first++;
              }
              size_t last = first + 2;
              while (last + 1 < frames.size() && !frames[last + 1].info.restart())
              {
                  last++;
              }
              auto* dctx = ZSTD_createDCtx();
              auto* cctx = ZSTD_createCCtx();
              ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 1);
              ZSTD_CCtx_setParameter(cctx, ZSTD_c_contentSizeFlag, 0);
              std::vector<uint8_t> rebuilt;
              for (size_t i = first; i <= last; ++i)
              {
                  const auto&          f = frames[i];
                  std::vector<uint8_t> plain(f.info.plainSize);
                  ZSTD_inBuffer        in{ bytes.data() + f.offset + sizeof(FrameHeader), f.info.payloadSize, 0 };
                  ZSTD_outBuffer       out{ plain.data(), plain.size(), 0 };
                  expect(!ZSTD_isError(ZSTD_decompressStream(dctx, &out, &in)) && in.pos == in.size && out.pos == out.size, "the stream decodes");
                  if (i == first + 1)
                  {
                      plain.push_back(0); // a byte after the last group: the group sizes no longer add up
                  }
                  std::vector<uint8_t> packed(ZSTD_compressBound(plain.size()) + 64);
                  ZSTD_inBuffer        pin{ plain.data(), plain.size(), 0 };
                  ZSTD_outBuffer       pout{ packed.data(), packed.size(), 0 };
                  ZSTD_compressStream2(cctx, &pout, &pin, ZSTD_e_flush);
                  packed.resize(pout.pos);
                  auto header        = podAt<FrameHeader>(bytes, f.offset);
                  header.payloadSize = static_cast<uint32_t>(packed.size());
                  header.plainSize   = static_cast<uint32_t>(plain.size());
                  const auto frame   = frameBytes(header, packed);
                  rebuilt.insert(rebuilt.end(), frame.begin(), frame.end());
              }
              ZSTD_freeDCtx(dctx);
              ZSTD_freeCCtx(cctx);
              const auto start = frames[first].offset;
              save(p, splice(bytes, start, frames[last].offset + frames[last].size - start, rebuilt));
              uint64_t before = 0;
              uint64_t after  = 0;
              for (size_t i = 0; i < frames.size(); ++i)
              {
                  if (i <= first)
                  {
                      before += frames[i].info.packetCount;
                  }
                  else if (i > last)
                  {
                      after += frames[i].info.packetCount;
                  }
              }
              expect(count(p) == before && count(p, { .recovery = true }) == before + after, "a bad plaintext ends its stream, though its zstd decodes");
          } },
        { "sealed", [&](const fs::path& p)
          {
              session(tmp, 6, shortStreams());
              seal(tmp, p);
              const auto v = Reader(p).verify();
              expect(v.signedToEnd && v.seal && v.seal->good, "sealed keeps the recorder's signature and adds a good seal");
          } },
        { "sealed-cut-off", [&](const fs::path& p)
          {
              session(tmp, 7, shortStreams());
              auto bytes = cutOff(tmp);
              bytes.resize(bytes.size() - 5);
              save(tmp2, bytes);
              const auto before = Reader(tmp2).verify();
              seal(tmp2, p);
              const auto v = Reader(p).verify();
              expect(before.verifiedPackets > 0 && v.verifiedPackets == before.verifiedPackets && !v.signedToEnd && v.seal && v.seal->good, "sealed-cut-off carries its last checkpoint");
          } },
        { "converted", [&](const fs::path& p)
          {
              auto cfg        = config();
              cfg.origin      = Origin::Converted;
              cfg.clockSource = ClockSource::Converted;
              cfg.source      = SourceInfo{ .format = "xicap", .formatVersion = "3.0", .skippedRecords = 2, .utcOffsetSeconds = -3600, .sourceHash = {}, .metadata = { 'c', 'a', 'p', 't', 'u', 'r', 'e', ' ', 'x' } };
              cfg.source->sourceHash.fill(0xAB);
              Writer w(p, cfg);
              w.write(T0, PacketDirection::ServerToClient, zoneIn(230, 1));
              w.write(T0 + 10, PacketDirection::ServerToClient, game(0x0DF, 16, 1, 2));
              w.write(T0 + 20, PacketDirection::ServerToClient, game(0x0DF, 16, 2, 3));
              w.close();
              Reader r(p);
              expect(r.source() && r.source()->skippedRecords == 2 && r.verify().signedToEnd, "converted names its source");
          } },
        { "chat-kept", [&](const fs::path& p)
          {
              auto cfg   = config();
              cfg.policy = { .name = "none", .version = 1, .rules = {} };
              Writer w(p, cfg);
              w.write(T0, PacketDirection::ServerToClient, zoneIn(230, 1));
              w.write(T0 + 10, PacketDirection::ServerToClient, game(0x017, 32, 'x', 2)); // chat: kept
              w.close();
              Reader r(p);
              expect(!coversDefault(r.policy()) && count(p) == 2, "a policy with no rules keeps chat");
          } },
        { "edited-packet", [&](const fs::path& p)
          {
              session(tmp, 3, alone());
              const auto bytes = cutOff(tmp);
              const auto f     = packetFrames(bytes)[1];
              auto       plain = plainOf(bytes, f);
              plain.back() ^= 0x01; // the last byte of the frame's last packet
              save(p, splice(bytes, f.offset, f.size, packetFrame(podAt<FrameHeader>(bytes, f.offset), plain)));
              const auto v = Reader(p).verify();
              expect(count(p) == 9 && v.firstFailureOffset && v.verifiedPackets == 0, "an edited packet reads, and the checkpoint over it fails");
          } },
        { "character-mismatch", [&](const fs::path& p)
          {
              Writer w(p, config());
              auto   other = zoneIn(230, 1);
              std::memcpy(other.data() + FFXIPacket::LOGIN_NAME_OFFSET, "Other\0", 6);
              w.write(T0, PacketDirection::ServerToClient, other);
              w.close();
              Reader     r(p);
              ReadPacket pk{};
              while (r.next(pk))
              {
              }
              expect(r.characterMismatch(), "a zone-in naming another character reads, and is reported");
          } },
        { "bad-header-crc", [&](const fs::path& p)
          {
              session(tmp, 1, alone());
              auto bytes = bytesOf(tmp);
              bytes[offsetof(Header, clientVersion)] ^= 0x01;
              save(p, bytes);
              expect(refuses(p, ErrorCode::HeaderChecksumMismatch), "a header whose CRC fails is refused");
          } },
        { "bad-extension-crc", [&](const fs::path& p)
          {
              session(tmp, 1, alone());
              auto bytes = bytesOf(tmp);
              bytes[HEADER_SIZE + sizeof(ExtensionBlockHeader)] ^= 0x01; // the policy's name
              save(p, bytes);
              expect(refuses(p, ErrorCode::ExtensionChecksumMismatch), "a block whose CRC fails is refused");
          } },
        { "format-2", [&](const fs::path& p)
          {
              session(tmp, 1, alone());
              auto bytes = bytesOf(tmp);
              std::memcpy(bytes.data(), "XCAP", 4);
              save(p, bytes);
              expect(refuses(p, ErrorCode::BadMagic), "a format-2 magic is refused");
          } },
        { "version-3", [&](const fs::path& p)
          {
              session(tmp, 1, alone());
              auto bytes          = bytesOf(tmp);
              auto header         = podAt<Header>(bytes, 0);
              header.versionMajor = 3;
              header.headerCrc    = internal::crc32({ reinterpret_cast<const uint8_t*>(&header), offsetof(Header, headerCrc) });
              std::memcpy(bytes.data(), &header, sizeof(header));
              save(p, bytes);
              expect(refuses(p, ErrorCode::UnsupportedVersion), "format 3 is refused");
          } },
        { "unknown-skippable-kind", [&](const fs::path& p)
          {
              session(tmp, 2, alone());
              const auto                   bytes = cutOff(tmp);
              const std::array<uint8_t, 3> payload{ 1, 2, 3 };
              save(p, splice(bytes, packetFrames(bytes)[1].offset, 0, frameBytes(FrameHeader{ .magic = FRAME_MAGIC, .kind = static_cast<FrameKind>(0x02), .frameFlags = 0, .markerCount = 0, .payloadSize = 3, .packetCount = 0, .baseTimestamp = T0, .zoneId = 0, .reserved = 0, .plainSize = 0 }, payload)));
              expect(count(p) == 6, "an unknown skippable frame is skipped");
          } },
        { "unknown-required-kind", [&](const fs::path& p)
          {
              session(tmp, 2, alone());
              const auto                   bytes = cutOff(tmp);
              const std::array<uint8_t, 3> payload{ 1, 2, 3 };
              save(p, splice(bytes, packetFrames(bytes)[1].offset, 0, frameBytes(FrameHeader{ .magic = FRAME_MAGIC, .kind = static_cast<FrameKind>(0x81), .frameFlags = 0, .markerCount = 0, .payloadSize = 3, .packetCount = 0, .baseTimestamp = T0, .zoneId = 0, .reserved = 0, .plainSize = 0 }, payload)));
              expect(refuses(p, ErrorCode::UnknownFrameKind), "an unknown must-understand frame is refused");
          } },
        { "unknown-required-flag", [&](const fs::path& p)
          {
              auto plain = examplePlain();
              plain[3]   = 0x80;
              plain.insert(plain.begin() + 4, 0x08); // flags 0x400
              badMiddle(tmp, p, plain);
              expect(refuses(p, ErrorCode::UnknownPacketFlag), "an unknown must-understand flag is refused");
          } },
        { "dictionary-id", [&](const fs::path& p)
          {
              session(tmp, 1, alone());
              auto bytes          = bytesOf(tmp);
              auto header         = podAt<Header>(bytes, 0);
              header.dictionaryId = 0x0D1C7;
              header.headerCrc    = internal::crc32({ reinterpret_cast<const uint8_t*>(&header), offsetof(Header, headerCrc) });
              std::memcpy(bytes.data(), &header, sizeof(header));
              save(p, bytes);
              expect(refuses(p, ErrorCode::DictionaryMismatch), "a header naming a dictionary is refused");
          } },
        { "bad-varint", [&](const fs::path& p)
          {
              auto plain = examplePlain();
              plain[0]   = 0x80; // deltaMs 0 in six bytes
              plain.insert(plain.begin() + 1, { 0x80, 0x80, 0x80, 0x80, 0x00 });
              badMiddle(tmp, p, plain);
              expect(count(p) == 3 && count(p, { .recovery = true }) == 6, "a varint over five bytes is a bad frame");
          } },
        { "group-sizes", [&](const fs::path& p)
          {
              auto plain = examplePlain();
              plain[21]  = 0x2F;
              badMiddle(tmp, p, plain);
              expect(count(p) == 3 && count(p, { .recovery = true }) == 6, "group sizes that do not add up make a bad frame");
          } },
    };

    for (const auto& [name, make] : cases)
    {
        const auto path = dir / ("4-" + name + ".xicap");
        make(path);
        std::ofstream(dir / ("4-" + name + ".json"), std::ios::binary | std::ios::trunc) << vectors::reading(path);
        std::cout << "4-" << name << "\n";
    }
    fs::remove(tmp);
    fs::remove(tmp2);
    return 0;
}
