// Format 4: the column codec, streams, signatures, seals, transcode, and the stream reader.

#include "helpers.h"
#include "internal/access.h"
#include "internal/chain.h"
#include "internal/columns.h"
#include "internal/crc32.h"
#include "internal/transcode.h"
#include "internal/varint.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <format>
#include <random>
#include <string>
#include <vector>
#include <zstd.h>

using namespace test;
using namespace craft;

namespace
{

auto hexOf(std::span<const uint8_t> bytes) -> std::string
{
    std::string out;
    for (const auto b : bytes)
    {
        out += std::format("{:02x}", b);
    }
    return out;
}

auto refusal(const std::function<void()>& f) -> std::optional<ErrorCode>
{
    try
    {
        f();
    }
    catch (const Error& e)
    {
        return e.code();
    }
    return std::nullopt;
}

// Three 0x0DF packets to the client, 10 ms apart, with syncs 1, 2, and 3: FORMAT.md's example.
auto examplePackets() -> std::vector<std::vector<std::byte>>
{
    return { gamePacket(0x0DF, 16, 0, 1), gamePacket(0x0DF, 16, 1, 2), gamePacket(0x0DF, 16, 2, 3) };
}

const std::string EXAMPLE = "000a0a"
                            "000000"
                            "000000"
                            "df01df01df01"
                            "000000"
                            "020202"
                            "30"
                            "df080000000000000000000000000000"
                            "df080000010101010101010101010101"
                            "df080000020202020202020202020202";

auto fromHex(const std::string& hex) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

// A capture with markers and a checkpoint every two seconds: `frames` frames of three packets, one second apart.
auto session(const fs::path& path, int frames, FramePolicy policy = {}) -> void
{
    policy.checkpointIntervalMs = 2000;
    Writer w(path, config(), policy);
    w.mark(MarkerKind::Login, "in");
    for (int f = 0; f < frames; ++f)
    {
        for (int i = 0; i < 3; ++i)
        {
            if (i == 1)
            {
                w.mark(MarkerKind::Note, std::format("frame {}", f));
            }
            w.write(T0 + static_cast<uint64_t>(f) * 1000 + static_cast<uint64_t>(i), i % 2 ? PacketDirection::ClientToServer : PacketDirection::ServerToClient, gamePacket(static_cast<uint16_t>(0x100 + f % 5), 24, static_cast<uint8_t>(f), static_cast<uint16_t>(f * 3 + i)));
        }
        w.flush();
    }
    w.close();
}

// Small frames and streams of a few frames each.
auto shortStreams() -> FramePolicy
{
    auto p         = FramePolicy::live();
    p.maxFrameSize = 128;
    p.restartBytes = 400;
    return p;
}

auto mogsafe() -> TranscodeOptions
{
    return { .policy = FramePolicy::archive(), .signing = Signing::Seal, .seed = seed(9), .agent = "mogsafe test", .sourceHash = {}, .metadata = {} };
}

auto key(const SecretSeed& s) -> PublicKey
{
    return internal::SigningKey(s).publicKey();
}

auto vectorFiles() -> std::vector<fs::path>
{
    std::vector<fs::path> out;
    for (const auto& entry : fs::directory_iterator(XICAP_VECTORS_DIR))
    {
        if (entry.path().extension() == ".xicap")
        {
            out.push_back(entry.path());
        }
    }
    std::ranges::sort(out);
    return out;
}

// Splices frames into a complete file and rewrites its index and trailer to match, keeping the footer's signature.
// `frames` is how many frames the splice adds.
auto spliceComplete(const std::vector<uint8_t>& bytes, size_t at, size_t remove, std::span<const uint8_t> insert, int frames = 0) -> std::vector<uint8_t>
{
    auto                          trailer = podAt<FooterTrailer>(bytes, bytes.size() - sizeof(FooterTrailer));
    const auto                    shift   = static_cast<int64_t>(insert.size()) - static_cast<int64_t>(remove);
    std::vector<FooterIndexEntry> index(trailer.entryCount);
    std::memcpy(index.data(), bytes.data() + trailer.indexOffset, index.size() * sizeof(FooterIndexEntry));
    for (auto& e : index)
    {
        e.fileOffset = e.fileOffset >= at + remove ? static_cast<uint64_t>(static_cast<int64_t>(e.fileOffset) + shift) : e.fileOffset;
    }
    std::vector<uint8_t> out(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(trailer.indexOffset));
    out                 = splice(out, at, remove, insert);
    trailer.indexOffset = out.size();
    trailer.frameCount  = static_cast<uint32_t>(static_cast<int64_t>(trailer.frameCount) + frames);
    trailer.indexCrc    = internal::crc32({ reinterpret_cast<const uint8_t*>(index.data()), index.size() * sizeof(FooterIndexEntry) });
    trailer.trailerCrc  = internal::crc32({ reinterpret_cast<const uint8_t*>(&trailer), offsetof(FooterTrailer, trailerCrc) });
    const auto* idx     = reinterpret_cast<const uint8_t*>(index.data());
    out.insert(out.end(), idx, idx + index.size() * sizeof(FooterIndexEntry));
    const auto* t = reinterpret_cast<const uint8_t*>(&trailer);
    out.insert(out.end(), t, t + sizeof(trailer));
    return out;
}

auto refused(const fs::path& path) -> bool
{
    return refusal([&]
                   {
                       readAll(path);
                   })
        .has_value();
}

} // namespace

TEST_CASE("varints round-trip at each length and refuse what breaks the rules")
{
    for (unsigned bytes = 1; bytes <= 5; ++bytes)
    {
        const uint64_t lowest  = bytes == 1 ? 0 : uint64_t{ 1 } << (7 * (bytes - 1));
        const uint64_t highest = std::min<uint64_t>((uint64_t{ 1 } << (7 * bytes)) - 1, UINT32_MAX);
        for (const auto value : { lowest, highest })
        {
            std::vector<uint8_t> out;
            internal::putVarint(out, value);
            CHECK(out.size() == bytes);
            CHECK(internal::varintSize(value) == bytes);
            size_t   pos  = 0;
            uint32_t back = 0;
            REQUIRE(internal::getVarint(out, pos, 32, back));
            CHECK(back == value);
            CHECK(pos == out.size());
        }
    }
    const auto reads = [](std::vector<uint8_t> in, unsigned bits)
    {
        size_t   pos = 0;
        uint32_t out = 0;
        return internal::getVarint(in, pos, bits, out);
    };
    CHECK_FALSE(reads({ 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 }, 32)); // 6 bytes for 32 bits
    CHECK_FALSE(reads({ 0x80, 0x80, 0x80, 0x80, 0x10 }, 32));       // 2^32
    CHECK(reads({ 0xFF, 0xFF, 0xFF, 0xFF, 0x0F }, 32));             // 2^32 - 1
    CHECK_FALSE(reads({ 0x80, 0x80, 0x04 }, 16));                   // 65536
    CHECK(reads({ 0xFF, 0xFF, 0x03 }, 16));                         // 65535
    CHECK_FALSE(reads({ 0x80, 0x80, 0x80, 0x00 }, 16));             // 4 bytes for 16 bits
    CHECK_FALSE(reads({ 0x80, 0x02 }, 8));                          // 256
    CHECK(reads({ 0xFF, 0x01 }, 8));                                // 255
    CHECK_FALSE(reads({ 0x80 }, 32));                               // runs past the end

    CHECK(internal::zigzag16(0) == 0);
    CHECK(internal::zigzag16(-1) == 1);
    CHECK(internal::zigzag16(1) == 2);
    CHECK(internal::zigzag16(INT16_MAX) == 65534);
    CHECK(internal::zigzag16(INT16_MIN) == 65535);
    for (int n = INT16_MIN; n <= INT16_MAX; ++n)
    {
        REQUIRE(internal::unzigzag16(internal::zigzag16(static_cast<int16_t>(n))) == n);
    }
}

TEST_CASE("the worked example encodes to its 70 bytes and back")
{
    const auto                    packets = examplePackets();
    std::vector<internal::Record> records;
    for (size_t i = 0; i < packets.size(); ++i)
    {
        records.push_back({ .timestamp = T0 + i * 10, .flags = 0, .channel = 0, .opcode = 0x0DF, .data = { reinterpret_cast<const uint8_t*>(packets[i].data()), 16 } });
    }
    const auto plain = internal::encodeColumns(records, {});
    CHECK(plain.size() == 70);
    CHECK(hexOf(plain) == EXAMPLE);

    internal::DecodedFrame frame;
    internal::decodeColumns(plain, 3, 0, T0, frame);
    REQUIRE(frame.packets.size() == 3);
    for (size_t i = 0; i < 3; ++i)
    {
        const auto& p = frame.packets[i];
        CHECK(p.timestamp == T0 + i * 10);
        CHECK(p.opcode == 0x0DF);
        CHECK(std::ranges::equal(std::span{ frame.bytes }.subspan(p.offset, p.length), records[i].data));
    }
}

TEST_CASE("the column decoder refuses bad frames")
{
    const auto bad = [](const std::vector<uint8_t>& plain, uint16_t markers = 0)
    {
        internal::DecodedFrame frame;
        return refusal([&]
                       {
                           internal::decodeColumns(plain, 3, markers, T0, frame);
                       });
    };
    auto plain = fromHex(EXAMPLE);
    CHECK_FALSE(bad(plain));

    SECTION("a section past the end")
    {
        CHECK(bad({ plain.begin(), plain.begin() + 20 }) == ErrorCode::CorruptFrame);
        CHECK(bad({ plain.begin(), plain.end() - 1 }) == ErrorCode::CorruptFrame);
    }
    SECTION("group sizes that do not add up")
    {
        plain[21] = 0x2F;
        CHECK(bad(plain) == ErrorCode::CorruptFrame);
    }
    SECTION("group bytes left over")
    {
        plain[21] = 0x31;
        plain.push_back(0);
        CHECK(bad(plain) == ErrorCode::CorruptFrame);
    }
    SECTION("a game packet under 4 bytes")
    {
        plain[15] = 0x04; // packet 0: explicit length 3
        CHECK(bad(plain) == ErrorCode::CorruptFrame);
    }
    SECTION("an opcode that is not the header's id")
    {
        plain[9] = 0xE0;
        CHECK(bad(plain) == ErrorCode::CorruptFrame);
    }
    SECTION("a marker out of range, or going backwards")
    {
        const auto withMarkers = [&](std::vector<uint8_t> markers)
        {
            auto out = plain;
            out.insert(out.begin() + 21, markers.begin(), markers.end());
            return out;
        };
        CHECK_FALSE(bad(withMarkers({ 0x02, 0x00, 0x00 }), 1));
        CHECK(bad(withMarkers({ 0x03, 0x00, 0x00 }), 1) == ErrorCode::CorruptFrame);
        CHECK(bad(withMarkers({ 0x02, 0x00, 0x00, 0x01, 0x00, 0x00 }), 2) == ErrorCode::CorruptFrame);
    }
    SECTION("a flag that must be understood")
    {
        plain[3] = 0x80;
        plain.insert(plain.begin() + 4, 0x08); // 0x400
        CHECK(bad(plain) == ErrorCode::UnknownPacketFlag);
    }
}

TEST_CASE("streams restart every 4 MiB and each frame is on disk as written")
{
    TempCapture tmp;

    SECTION("a 40 MiB capture")
    {
        std::mt19937 rng(1);
        uint64_t     written = 0;
        {
            Writer   w(tmp.path, config());
            uint64_t t = T0;
            for (uint16_t sync = 0; written < 40 * 1024 * 1024; ++sync)
            {
                auto p = gamePacket(static_cast<uint16_t>(0x100 + sync % 7), 200, static_cast<uint8_t>(sync), sync);
                for (size_t i = 100; i < p.size(); ++i)
                {
                    p[i] = std::byte(rng() & 0x0F);
                }
                w.write(t += 7, PacketDirection::ServerToClient, p);
                written += p.size();
            }
            w.close();
        }
        const auto bytes   = bytesOf(tmp.path);
        const auto frames  = packetFrames(bytes);
        uint64_t   plain   = 0;
        size_t     restart = 0;
        size_t     streams = 0;
        const auto ends    = [&](size_t first, size_t last)
        {
            std::vector<uint8_t> payload;
            for (size_t i = first; i < last; ++i)
            {
                const auto* p = bytes.data() + frames[i].offset + sizeof(FrameHeader);
                payload.insert(payload.end(), p, p + frames[i].info.payloadSize);
            }
            return ZSTD_findFrameCompressedSize(payload.data(), payload.size()) == payload.size();
        };
        REQUIRE(frames.front().info.restart());
        for (size_t i = 0; i < frames.size(); ++i)
        {
            if (i > 0 && frames[i].info.restart())
            {
                CHECK(plain <= 4 * 1024 * 1024);
                CHECK(ends(restart, i));
                restart = i;
                plain   = 0;
                streams++;
            }
            plain += frames[i].info.plainSize;
        }
        CHECK(plain <= 4 * 1024 * 1024);
        CHECK(ends(restart, frames.size()));
        CHECK(streams >= 9);
        CHECK(readAll(tmp.path).size() == written / 200);
    }
    SECTION("a copy taken after each frame reads every packet so far")
    {
        Writer w(tmp.path, config(), shortStreams());
        for (int f = 0; f < 30; ++f)
        {
            for (int i = 0; i < 4; ++i)
            {
                w.write(T0 + static_cast<uint64_t>(f * 4 + i), PacketDirection::ServerToClient, gamePacket(0x0DF, 32, static_cast<uint8_t>(f), static_cast<uint16_t>(f * 4 + i)));
            }
            w.flush();
            TempCapture copy;
            fs::copy_file(tmp.path, copy.path);
            Reader r(copy.path);
            CHECK_FALSE(r.complete());
            CHECK(readAll(r).size() == static_cast<size_t>(f + 1) * 4);
            CHECK(r.unreadBytes() == 0);
        }
        w.close();
    }
}

TEST_CASE("the footer signs D(end), computed by hand")
{
    TempCapture tmp;
    {
        Writer     w(tmp.path, config());
        const auto packets = examplePackets();
        for (size_t i = 0; i < packets.size(); ++i)
        {
            w.write(T0 + i * 10, PacketDirection::ServerToClient, packets[i]);
        }
        w.close();
    }
    const auto           bytes     = bytesOf(tmp.path);
    const auto           dataStart = framesOf(bytes).at(0).offset;
    std::vector<uint8_t> stream(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(dataStart));
    const auto           put = [&](const auto& v)
    {
        const auto* p = reinterpret_cast<const uint8_t*>(&v);
        stream.insert(stream.end(), p, p + sizeof(v));
    };
    for (size_t i = 0; i < 3; ++i)
    {
        stream.push_back('P');
        put(uint64_t{ T0 + i * 10 });
        put(uint16_t{ 0 });
        put(uint8_t{ 0 });
        put(uint16_t{ 0x0DF });
        put(uint32_t{ 16 });
        const auto data = gamePacket(0x0DF, 16, static_cast<uint8_t>(i), static_cast<uint16_t>(i + 1));
        stream.insert(stream.end(), reinterpret_cast<const uint8_t*>(data.data()), reinterpret_cast<const uint8_t*>(data.data()) + 16);
    }
    stream.push_back('E');
    put(uint64_t{ 3 });
    put(uint64_t{ T0 + 20 });
    Digest end{};
    crypto_sha512(end.data(), stream.data(), stream.size());

    const auto           trailer = podAt<FooterTrailer>(bytes, bytes.size() - sizeof(FooterTrailer));
    std::vector<uint8_t> message{ 'x', 'i', 'c', 'a', 'p', '/', '4', ' ', 'f', 'o', 'o', 't', 'e', 'r' };
    message.insert(message.end(), end.begin(), end.end());
    CHECK(crypto_ed25519_check(trailer.signature.data(), key(seed()).data(), message.data(), message.size()) == 0);
    CHECK(Reader(tmp.path).verify().signedToEnd);
}

TEST_CASE("checkpoints sit where their packet count says")
{
    TempCapture tmp;
    session(tmp.path, 8, alone());
    auto       bytes = bytesOf(tmp.path);
    const auto all   = Reader(tmp.path).verify();
    CHECK(all.signedToEnd);
    CHECK(all.goodCheckpoints == 2);

    bytes.resize(footerOffset(bytes));
    const auto frames = framesOf(bytes);
    auto       second = frames.end();
    for (auto it = frames.begin(); it != frames.end(); ++it)
    {
        if (it->info.kind == FrameKind::Checkpoint)
        {
            second = it;
        }
    }
    REQUIRE(second != frames.end());
    REQUIRE(std::next(second) != frames.end());
    // Move the checkpoint one packet frame later: its digest still matches its count, but not its place.
    const std::vector<uint8_t> checkpoint(bytes.begin() + static_cast<std::ptrdiff_t>(second->offset), bytes.begin() + static_cast<std::ptrdiff_t>(second->offset + second->size));
    auto                       moved = splice(bytes, second->offset, second->size, {});
    moved                            = splice(moved, second->offset + std::next(second)->size, 0, checkpoint);
    save(tmp.path, moved);
    Reader     r(tmp.path);
    const auto v = r.verify();
    CHECK(readAll(r).size() == 24);
    CHECK(v.firstFailureOffset == second->offset + std::next(second)->size);
    CHECK(v.goodCheckpoints == 1);
}

TEST_CASE("a bad checkpoint is reported but does not hide a later signature")
{
    TempCapture tmp;
    session(tmp.path, 8, alone());
    const auto bytes  = bytesOf(tmp.path);
    const auto frames = framesOf(bytes);
    const auto first  = std::ranges::find_if(frames, [](const FrameRef& f)
                                             {
                                                return f.info.kind == FrameKind::Checkpoint;
                                             });
    REQUIRE(first != frames.end());
    std::vector<uint8_t> payload(bytes.begin() + static_cast<std::ptrdiff_t>(first->offset + sizeof(FrameHeader)),
                                 bytes.begin() + static_cast<std::ptrdiff_t>(first->offset + sizeof(FrameHeader) + sizeof(CheckpointPayload)));
    SECTION("a bad signature")
    {
        payload.back() ^= 1;
    }
    SECTION("a payload of the wrong size")
    {
        payload.pop_back();
    }
    auto header        = podAt<FrameHeader>(bytes, first->offset);
    header.payloadSize = static_cast<uint32_t>(payload.size());
    save(tmp.path, spliceComplete(bytes, first->offset, first->size, frameBytes(header, payload)));

    Reader     r(tmp.path);
    const auto v = r.verify();
    CHECK(r.complete());
    CHECK(v.firstFailureOffset == first->offset);
    CHECK(v.signedToEnd);
    CHECK(v.verifiedPackets == 24);
    CHECK(v.goodCheckpoints == 1);

    // Cut off: the later checkpoint still counts.
    auto cut = bytesOf(tmp.path);
    cut.resize(footerOffset(cut));
    save(tmp.path, cut);
    const auto c = Reader(tmp.path).verify();
    CHECK(c.firstFailureOffset == first->offset);
    CHECK(c.goodCheckpoints == 1);
    CHECK(c.verifiedPackets > 0);
}

TEST_CASE("verify refuses a frame kind it must understand")
{
    TempCapture tmp;
    writeFrames(tmp.path, 2);
    const auto bytes = bytesOf(tmp.path);
    const auto frame = frameBytes(FrameHeader{ .magic = FRAME_MAGIC, .kind = static_cast<FrameKind>(0x81), .frameFlags = 0, .markerCount = 0, .payloadSize = 0, .packetCount = 0, .baseTimestamp = 0, .zoneId = 0, .reserved = 0, .plainSize = 0 }, {});
    save(tmp.path, spliceComplete(bytes, packetFrames(bytes).at(1).offset, 0, frame, 1));
    Reader r(tmp.path);
    REQUIRE(r.complete());
    CHECK(refusal([&]
                  {
                      (void)r.verify();
                  }) == ErrorCode::UnknownFrameKind);
}

TEST_CASE("one changed packet fails the footer, and every packet still reads")
{
    TempCapture src;
    TempCapture dst;
    session(src.path, 4);
    const auto original = readAll(src.path);

    const auto edited = [&](const std::function<void(internal::CopiedPacket&)>& edit)
    {
        internal::transcode(src.path, dst.path, mogsafe(), { .edit = [&](uint64_t index, internal::CopiedPacket& p)
                                                             {
                                                                 if (index == 7)
                                                                 {
                                                                     edit(p);
                                                                 }
                                                             },
                                                             .check = false });
        Reader     r(dst.path);
        const auto packets = readAll(r);
        const auto v       = r.verify();
        CHECK(r.complete());
        CHECK(packets.size() == original.size());
        CHECK(packets[7] != original[7]);
        CHECK_FALSE(v.signedToEnd);
        CHECK(v.firstFailureOffset);
    };
    SECTION("a byte")
    {
        edited([](internal::CopiedPacket& p)
               {
                   p.data[10] ^= 1;
               });
    }
    SECTION("a time")
    {
        edited([](internal::CopiedPacket& p)
               {
                   p.timestamp -= 1;
               });
    }
    SECTION("a flag")
    {
        edited([](internal::CopiedPacket& p)
               {
                   p.flags ^= PacketFlag::Modified;
               });
    }
    SECTION("a marker")
    {
        edited([](internal::CopiedPacket& p)
               {
                   REQUIRE_FALSE(p.markers.empty());
                   p.markers[0].text += "!";
               });
    }
}

TEST_CASE("the footer reports seals, unsigned ends, and damage")
{
    TempCapture src;
    TempCapture dst;
    session(src.path, 4);

    SECTION("a sealed file")
    {
        transcode(src.path, dst.path, mogsafe());
        Reader     r(dst.path);
        const auto v = r.verify();
        CHECK(r.complete());
        CHECK(v.signedToEnd);
        CHECK(v.key == key(seed()));
        REQUIRE(v.seal);
        CHECK(v.seal->good);
        CHECK(v.seal->key == key(seed(9)));
        CHECK(v.seal->agent == "mogsafe test");
        CHECK(v.seal->sealedAt > T0 - 1'000'000'000'000);
        CHECK_FALSE(Reader(src.path).verify().seal);
    }
    SECTION("a seal with a bad CRC is a damaged footer")
    {
        transcode(src.path, dst.path, mogsafe());
        auto bytes = bytesOf(dst.path);
        bytes[bytes.size() - sizeof(FooterTrailer) - sizeof(SealBlock) + 50] ^= 1;
        save(dst.path, bytes);
        Reader r(dst.path);
        CHECK_FALSE(r.complete());
        CHECK(r.footerDamaged());
        CHECK(readAll(r).size() == 12);
    }
    SECTION("an unknown trailer bit reads as cut off")
    {
        auto bytes   = bytesOf(src.path);
        auto trailer = podAt<FooterTrailer>(bytes, bytes.size() - sizeof(FooterTrailer));
        trailer.trailerFlags |= 0x04;
        trailer.trailerCrc = internal::crc32({ reinterpret_cast<const uint8_t*>(&trailer), offsetof(FooterTrailer, trailerCrc) });
        std::memcpy(bytes.data() + bytes.size() - sizeof(FooterTrailer), &trailer, sizeof(trailer));
        save(src.path, bytes);
        Reader r(src.path);
        CHECK_FALSE(r.complete());
        CHECK(r.footerDamaged());
        CHECK(readAll(r).size() == 12);
    }
    SECTION("a file whose end the signer never signed")
    {
        auto bytes = bytesOf(src.path);
        bytes.resize(footerOffset(bytes));
        save(src.path, bytes);
        const auto cut = Reader(src.path).verify();
        REQUIRE(cut.verifiedPackets > 0);
        transcode(src.path, dst.path, mogsafe());
        Reader     r(dst.path);
        const auto v = r.verify();
        CHECK(r.complete());
        CHECK((internal::Access::trailer(r).trailerFlags & TrailerFlag::EndUnsigned) != 0);
        CHECK(internal::Access::trailer(r).signature == Signature{});
        CHECK_FALSE(v.signedToEnd);
        CHECK_FALSE(v.firstFailureOffset);
        CHECK(v.verifiedPackets == cut.verifiedPackets);
        CHECK(v.goodCheckpoints == 1);
        REQUIRE(v.seal);
        CHECK(v.seal->good);
    }
}

TEST_CASE("the reader reads both formats")
{
    TempCapture tmp;

    SECTION("it dispatches on the version")
    {
        CHECK(Reader(fs::path(XICAP_VECTORS_DIR) / "clean.xicap").versionMajor() == 3);
        writeFrames(tmp.path, 1);
        CHECK(Reader(tmp.path).versionMajor() == 4);
    }
    SECTION("it keeps the decoder across frames and resets it at restarts")
    {
        writeFrames(tmp.path, 20, 3, shortStreams());
        const auto frames   = packetFrames(bytesOf(tmp.path));
        const auto restarts = std::ranges::count_if(frames, [](const FrameRef& f)
                                                    {
                                                        return f.info.restart();
                                                    });
        CHECK(restarts > 2);
        CHECK(restarts < static_cast<std::ptrdiff_t>(frames.size()));
        const auto packets = readAll(tmp.path);
        REQUIRE(packets.size() == 60);
        CHECK(packets[59].data[2] == 59); // sync put back
        CHECK(Reader(tmp.path).verify().signedToEnd);
    }
    SECTION("it checks a frame's sizes and window before decoding it")
    {
        writeFrames(tmp.path, 2, 3, alone());
        auto bytes = bytesOf(tmp.path);
        bytes.resize(footerOffset(bytes));
        const auto frames = framesOf(bytes);
        const auto edit   = [&](const std::function<void(FrameHeader&)>& change)
        {
            auto header = podAt<FrameHeader>(bytes, frames[1].offset);
            change(header);
            std::vector<uint8_t> payload(bytes.begin() + static_cast<std::ptrdiff_t>(frames[1].offset + sizeof(FrameHeader)), bytes.begin() + static_cast<std::ptrdiff_t>(frames[1].offset + frames[1].size - 4));
            save(tmp.path, splice(bytes, frames[1].offset, frames[1].size, frameBytes(header, payload)));
            return readAll(tmp.path).size();
        };
        CHECK(edit([](FrameHeader& h)
                   {
                       h.plainSize = FrameLimits::MAX_CONTENT_SIZE + 1;
                   }) == 3);
        CHECK(edit([](FrameHeader& h)
                   {
                       h.packetCount = 0;
                   }) == 3);
        CHECK(edit([](FrameHeader& h)
                   {
                       h.packetCount = FrameLimits::MAX_PACKETS + 1;
                   }) == 3);

        // A stream whose window is 2^24.
        const auto plain = plainOf(bytes, frames[1]);
        auto*      cctx  = ZSTD_createCCtx();
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, 24);
        ZSTD_CCtx_setParameter(cctx, ZSTD_c_contentSizeFlag, 0);
        std::vector<uint8_t> out(ZSTD_compressBound(plain.size()) + 64);
        ZSTD_inBuffer        in{ plain.data(), plain.size(), 0 };
        ZSTD_outBuffer       o{ out.data(), out.size(), 0 };
        ZSTD_compressStream2(cctx, &o, &in, ZSTD_e_flush);
        ZSTD_compressStream2(cctx, &o, &in, ZSTD_e_end);
        ZSTD_freeCCtx(cctx);
        out.resize(o.pos);
        auto header        = podAt<FrameHeader>(bytes, frames[1].offset);
        header.payloadSize = static_cast<uint32_t>(out.size());
        save(tmp.path, splice(bytes, frames[1].offset, frames[1].size, frameBytes(header, out)));
        CHECK(readAll(tmp.path).size() == 3);
    }
    SECTION("a file cut off mid-stream reads up to its last whole frame")
    {
        Writer w(tmp.path, config());
        for (int f = 0; f < 5; ++f)
        {
            w.write(T0 + static_cast<uint64_t>(f), PacketDirection::ServerToClient, gamePacket(0x0DF, 16, static_cast<uint8_t>(f)));
            w.flush();
        }
        const auto frames = packetFrames(bytesOf(tmp.path));
        REQUIRE(frames.size() == 5);
        CHECK_FALSE(frames[3].info.restart());
        truncateAt(tmp.path, frames[3].offset + frames[3].size + 7);
        Reader r(tmp.path);
        CHECK(readAll(r).size() == 4);
        CHECK(r.unreadBytes() == 7);
    }
    SECTION("recovery resumes at the next restart")
    {
        writeFrames(tmp.path, 20, 3, shortStreams());
        auto       bytes  = bytesOf(tmp.path);
        const auto frames = packetFrames(bytes);
        // Damage the first frame that continues a stream, after the first restart.
        size_t damaged = 1;
        while (frames[damaged].info.restart())
        {
            damaged++;
        }
        size_t next = damaged + 1;
        while (!frames[next].info.restart())
        {
            next++;
        }
        bytes[frames[damaged].offset + sizeof(FrameHeader) + 2] ^= 0x55;
        save(tmp.path, bytes);
        CHECK(refused(tmp.path));
        Reader     r(tmp.path, { .recovery = true });
        const auto packets = readAll(r);
        CHECK(packets.size() == 60 - (next - damaged) * 3);
        REQUIRE(r.skippedRegions().size() == 1);
        CHECK(r.skippedRegions()[0].offset == frames[damaged].offset);
        CHECK(r.skippedRegions()[0].offset + r.skippedRegions()[0].length == frames[next].offset);
    }
    SECTION("seeks decode from the nearest restart")
    {
        Writer w(tmp.path, config(), shortStreams());
        for (int f = 0; f < 12; ++f)
        {
            if (f % 4 == 0)
            {
                w.write(T0 + static_cast<uint64_t>(f) * 1000, PacketDirection::ServerToClient, zoneIn(static_cast<uint16_t>(100 + f)));
            }
            for (int i = 0; i < 3; ++i)
            {
                w.write(T0 + static_cast<uint64_t>(f) * 1000 + 1 + static_cast<uint64_t>(i), PacketDirection::ServerToClient, gamePacket(0x0DF, 16, static_cast<uint8_t>(f), static_cast<uint16_t>(f * 3 + i)));
            }
            w.flush();
        }
        w.close();
        Reader r(tmp.path);
        size_t continuing = 0;
        for (uint64_t i = 0; i < r.totalFrames(); ++i)
        {
            REQUIRE(r.seekToFrame(i) == SeekResult::Ok);
            ReadPacket p{};
            REQUIRE(r.next(p));
            CHECK(p.timestamp == r.frameTimestamp(i));
            CHECK(r.currentFrameIndex() == i);
            continuing += (packetFrames(bytesOf(tmp.path))[i].info.restart() ? 0 : 1);
        }
        CHECK(continuing > 0);
        REQUIRE(r.seekToTime(T0 + 9002) == SeekResult::Ok);
        ReadPacket p{};
        REQUIRE(r.next(p));
        CHECK(p.timestamp == T0 + 9002);
        CHECK(std::to_integer<int>(p.data[2]) == 28);
        REQUIRE(r.seekToZone(108) == SeekResult::Ok);
        REQUIRE(r.next(p));
        CHECK(p.opcode == FFXIPacket::LOGIN_ZONE);
        CHECK(p.timestamp == T0 + 8000);
    }
}

TEST_CASE("transcode")
{
    TempCapture src;
    TempCapture dst;

    SECTION("Seal keeps the recorder's signature and adds a seal")
    {
        session(src.path, 6);
        const auto result = transcode(src.path, dst.path, mogsafe());
        CHECK(result.packets == 18);
        CHECK(result.markers == 7);
        CHECK(readAll(dst.path) == readAll(src.path));
        Reader     r(dst.path);
        const auto v = r.verify();
        CHECK(v.signedToEnd);
        CHECK(v.goodCheckpoints == 0); // the footer covers every packet
        REQUIRE(v.seal);
        CHECK(v.seal->good);
        Reader in(src.path);
        CHECK(internal::Access::headerBytes(r) == internal::Access::headerBytes(in));
        CHECK(internal::Access::blockBytes(r) == internal::Access::blockBytes(in));
    }
    SECTION("Seal of a cut-off recording carries its last good checkpoint")
    {
        session(src.path, 9);
        auto bytes = bytesOf(src.path);
        bytes.resize(footerOffset(bytes));
        bytes.resize(bytes.size() - 10); // and the last frame torn
        save(src.path, bytes);
        Reader     in(src.path);
        const auto before = in.verify();
        const auto read   = readAll(in);
        REQUIRE(before.verifiedPackets > 0);
        REQUIRE(before.verifiedPackets < read.size());

        transcode(src.path, dst.path, mogsafe());
        CHECK(readAll(dst.path) == read);
        Reader     r(dst.path);
        const auto v = r.verify();
        CHECK(r.complete());
        CHECK((internal::Access::trailer(r).trailerFlags & TrailerFlag::EndUnsigned) != 0);
        CHECK(v.key == key(seed()));
        CHECK(v.verifiedPackets == before.verifiedPackets);
        CHECK_FALSE(v.signedToEnd);
        REQUIRE(v.seal);
        CHECK(v.seal->good);
        const auto checkpoints = std::ranges::count_if(framesOf(bytesOf(dst.path)), [](const FrameRef& f)
                                                       {
                                                           return f.info.kind == FrameKind::Checkpoint;
                                                       });
        CHECK(checkpoints == 1);
    }
    SECTION("Seal of a recording cut off before any checkpoint carries none")
    {
        writeFrames(src.path, 3);
        truncateAt(src.path, footerOffset(bytesOf(src.path)));
        REQUIRE(Reader(src.path).verify().verifiedPackets == 0);
        transcode(src.path, dst.path, mogsafe());
        Reader     r(dst.path);
        const auto v = r.verify();
        CHECK(readAll(r).size() == 9);
        CHECK(v.verifiedPackets == 0);
        CHECK(v.goodCheckpoints == 0);
        REQUIRE(v.seal);
        CHECK(v.seal->good);
    }
    SECTION("Seal refuses format 3 and a complete file not signed to the end")
    {
        CHECK(refusal([&]
                      {
                          transcode(fs::path(XICAP_VECTORS_DIR) / "clean.xicap", dst.path, mogsafe());
                      }) == ErrorCode::TranscodeRefused);
        CHECK_FALSE(fs::exists(dst.path));
        writeFrames(src.path, 3);
        truncateAt(src.path, footerOffset(bytesOf(src.path)));
        TempCapture sealed;
        transcode(src.path, sealed.path, mogsafe());
        CHECK(refusal([&]
                      {
                          transcode(sealed.path, dst.path, mogsafe());
                      }) == ErrorCode::TranscodeRefused);
        CHECK_FALSE(fs::exists(dst.path));
    }
    SECTION("Resign of each format-3 vector keeps every packet and names its source")
    {
        auto options       = mogsafe();
        options.signing    = Signing::Resign;
        options.metadata   = { 'c', 'a', 'p', 't', 'u', 'r', 'e', ' ', 'x' };
        options.sourceHash = { 1, 2, 3 };
        size_t resigned    = 0;
        for (const auto& path : vectorFiles())
        {
            if (path.filename().string().starts_with("4-") || refused(path))
            {
                continue;
            }
            INFO(path.filename().string());
            Reader in(path);
            REQUIRE(in.versionMajor() == 3);
            const auto v = in.verify();
            transcode(path, dst.path, options);
            Reader     r(dst.path);
            const auto w = r.verify();
            CHECK(r.versionMajor() == 4);
            CHECK(w.signedToEnd);
            CHECK(w.key == key(seed(9)));
            CHECK(readAll(r) == readAll(path));
            CHECK(r.captureId() == in.captureId());
            CHECK(r.character().contentId == in.character().contentId);
            CHECK(r.policy().name == in.policy().name);
            REQUIRE(r.source());
            if (in.source())
            {
                CHECK(r.source()->format == in.source()->format);
                CHECK(r.source()->metadata == in.source()->metadata);
                continue;
            }
            const std::string metadata(r.source()->metadata.begin(), r.source()->metadata.end());
            CHECK(r.source()->format == "xicap");
            CHECK(r.source()->formatVersion == "3.0");
            CHECK(r.source()->sourceHash == options.sourceHash);
            CHECK(metadata.starts_with(std::format("signing-key {}\nsigned-to-end {}\nverified-packets {}\nfooter-signature ", hexOf(in.signingKey()), v.signedToEnd ? "yes" : "no", v.verifiedPackets)));
            CHECK(metadata.ends_with("transcoded-by mogsafe test\ncapture x"));
            resigned++;
        }
        CHECK(resigned >= 8);
    }
    SECTION("a difference leaves no file at dst")
    {
        session(src.path, 3);
        CHECK(refusal([&]
                      {
                          internal::transcode(src.path, dst.path, mogsafe(), { .edit = [](uint64_t index, internal::CopiedPacket& p)
                                                                               {
                                                                                   if (index == 4)
                                                                                   {
                                                                                       p.data.back() ^= 1;
                                                                                   }
                                                                               },
                                                                               .check = true });
                      }) == ErrorCode::TranscodeMismatch);
        CHECK_FALSE(fs::exists(dst.path));
        CHECK_FALSE(fs::exists(fs::path(dst.path).concat(".tmp")));
    }
}

TEST_CASE("the writer stores text as UTF-8, and copies keep markers whole")
{
    TempCapture src;
    TempCapture dst;
    // Ashita hands Memoria a note in Shift-JIS: 0x93 0x8C is not UTF-8.
    const std::string sjis = "\x93\x8c \xe6\x9d\xb1\xe4\xba\xac";
    {
        auto cfg         = config();
        cfg.captureAgent = "agent \xff";
        Writer w(src.path, cfg);
        w.mark(MarkerKind::Note, sjis);
        w.write(T0, PacketDirection::ServerToClient, gamePacket(0x0DF, 16));
        w.close();
    }
    Reader r(src.path);
    CHECK(r.captureAgent() == "agent \xef\xbf\xbd");
    const auto packets = readAll(r);
    REQUIRE(packets.size() == 1);
    REQUIRE(packets[0].markers.size() == 1);
    CHECK(packets[0].markers[0].text == "\xef\xbf\xbd\xef\xbf\xbd \xe6\x9d\xb1\xe4\xba\xac");

    // A marker of 2,000 bytes, which the format allows though this writer's mark() cuts at 1,024.
    const std::string longText(2000, 'x');
    TempCapture       long_;
    auto              options = mogsafe();
    options.signing           = Signing::Resign;
    internal::transcode(src.path, long_.path, options, { .edit = [&](uint64_t, internal::CopiedPacket& p)
                                                         {
                                                             p.markers[0].text = longText;
                                                         },
                                                         .check = false });
    REQUIRE(readAll(long_.path)[0].markers[0].text == longText);
    transcode(long_.path, dst.path, mogsafe());
    CHECK(readAll(dst.path)[0].markers[0].text == longText);
    cut(long_.path, dst.path, { .first = 0, .last = 0, .seed = seed(9), .agent = "cut", .sourceHash = {}, .metadata = {} });
    CHECK(readAll(dst.path)[0].markers[0].text == longText);
}

TEST_CASE("a cut carries the scene from before its range")
{
    TempCapture src;
    TempCapture dst;
    TempCapture again;
    // An NPC update: its id at byte 4 and the parts it sends at byte 10.
    const auto npc = [](uint32_t id, uint8_t parts)
    {
        auto p = gamePacket(0x00E, 40, 0);
        std::memcpy(p.data() + 4, &id, sizeof(id));
        p[10] = std::byte{ parts };
        return p;
    };
    {
        Writer w(src.path, config());
        w.write(T0, PacketDirection::ServerToClient, npc(1, 0x1F));                 // 0: another zone
        w.write(T0 + 1, PacketDirection::ServerToClient, zoneIn(100));              // 1: kept
        w.write(T0 + 2, PacketDirection::ServerToClient, npc(2, 0x18));             // 2: kept, its name and model
        w.write(T0 + 3, PacketDirection::ServerToClient, npc(2, 0x01));             // 3: its position, made stale by 4
        w.write(T0 + 4, PacketDirection::ServerToClient, npc(2, 0x05));             // 4: kept
        w.write(T0 + 5, PacketDirection::ServerToClient, npc(3, 0x1F));             // 5: gone at 6
        w.write(T0 + 6, PacketDirection::ServerToClient, npc(3, 0x20));             // 6: despawns 3
        w.write(T0 + 7, PacketDirection::ServerToClient, gamePacket(0x037, 32, 1)); // 7: made stale by 8
        w.write(T0 + 8, PacketDirection::ServerToClient, gamePacket(0x037, 32, 2)); // 8: kept
        w.write(T0 + 9, PacketDirection::ServerToClient, gamePacket(0x028, 32));    // 9: an event, not state
        w.write(T0 + 10, PacketDirection::ClientToServer, gamePacket(0x015, 32));   // 10: kept, the recorder's position
        w.mark(MarkerKind::Note, "cap start");
        w.write(T0 + 11, PacketDirection::ServerToClient, gamePacket(0x0DF, 16, 3)); // 11: the range
        w.write(T0 + 12, PacketDirection::ServerToClient, gamePacket(0x0DF, 16, 4)); // 12
        w.write(T0 + 13, PacketDirection::ServerToClient, gamePacket(0x0DF, 16, 5)); // 13: past it
        w.close();
    }
    const CutOptions options{ .first = 11, .last = 12, .seed = seed(9), .agent = "mogsafe", .sourceHash = {}, .metadata = {} };
    cut(src.path, dst.path, options);

    const auto from = readAll(src.path);
    const auto got  = readAll(dst.path);
    REQUIRE(got.size() == 7);
    const std::vector<size_t> carried{ 1, 2, 4, 8, 10 };
    for (size_t i = 0; i < carried.size(); ++i)
    {
        CHECK(got[i].flags == (from[carried[i]].flags | PacketFlag::Carried));
        CHECK(got[i].data == from[carried[i]].data);
        CHECK(got[i].timestamp == T0 + 11);
        CHECK(got[i].markers.empty());
    }
    CHECK(got[5] == from[11]);
    CHECK(got[6] == from[12]);

    Reader r(dst.path);
    CHECK(r.versionMinor() == 1);
    CHECK(r.startTimestamp() == T0 + 11);
    CHECK(r.verify().signedToEnd);

    cut(src.path, again.path, options);
    CHECK(craft::bytesOf(again.path) == craft::bytesOf(dst.path));

    // A cut from the first packet has nothing before it to carry.
    cut(src.path, again.path, { .first = 0, .last = 13, .seed = seed(9), .agent = "mogsafe", .sourceHash = {}, .metadata = {} });
    CHECK(readAll(again.path) == from);
}

TEST_CASE("the stream reader reads as the bytes arrive")
{
    TempCapture live;
    session(live.path, 30, shortStreams());
    std::vector<fs::path> files{ live.path };
    for (const auto& path : vectorFiles())
    {
        if (!refused(path))
        {
            files.push_back(path);
        }
    }
    for (const auto& path : files)
    {
        INFO(path.filename().string());
        const auto bytes    = bytesOf(path);
        const auto expected = readAll(path);
        const auto frames   = framesOf(bytes);
        size_t     largest  = frames.empty() ? bytes.size() : frames[0].offset; // the header and blocks
        for (const auto& f : frames)
        {
            largest = std::max(largest, f.size);
        }
        for (const size_t chunk : { size_t{ 1 }, size_t{ 7 }, size_t{ 4096 }, size_t{ 65536 } })
        {
            StreamReader       s;
            std::vector<Owned> got;
            for (size_t at = 0; at < bytes.size(); at += chunk)
            {
                s.push({ bytes.data() + at, std::min(chunk, bytes.size() - at) });
                CHECK((s.stopped() || s.unreadBytes() <= largest + chunk));
                ReadPacket p{};
                while (s.next(p))
                {
                    got.push_back(own(p));
                }
            }
            CHECK(s.ready());
            CHECK(got == expected);
        }
    }
}
