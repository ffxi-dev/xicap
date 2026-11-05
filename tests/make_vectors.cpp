// Writes the conformance vectors: tests/vectors/<name>.xicap and the reading each must give, <name>.json.
// Usage: make_vectors <dir>

#include "bytes/crc32.h"
#include "describe.h"
#include "format/layout.h"
#include "metadata/codec.h"
#include "support.h"

#include <zstd.h>

#include <bit>
#include <fstream>
#include <functional>
#include <iostream>

using namespace xicap;

namespace
{

using Bytes = std::vector<uint8_t>;

constexpr uint64_t T0 = 1'767'225'600'000; // 2026-01-01T00:00:00Z

// Overwrites the bytes at `at` with v.
template <typename T>
auto put(Bytes& b, const size_t at, const T& v) -> void
{
    std::ranges::copy(std::bit_cast<std::array<uint8_t, sizeof(T)>>(v), b.begin() + static_cast<std::ptrdiff_t>(at));
}

auto fixCrc(Bytes& b, const size_t from, const size_t to) -> void
{
    put(b, to - 4, bytes::crc32(std::span{ b }.subspan(from, to - 4 - from)));
}

struct Layout
{
    size_t                                 blocksEnd{};
    std::vector<std::pair<size_t, size_t>> blocks; // offset, size
    std::vector<std::pair<size_t, size_t>> frames;
};

auto layout(const Bytes& b) -> Layout
{
    Layout l;
    size_t at{ sizeof(format::Header) };
    for (size_t i{ 0 }; i < b[11]; ++i)
    {
        const auto size = size_t{ 12 } + bytes::load<uint32_t>(std::span{ b }, at + 4);
        l.blocks.emplace_back(at, size);
        at += size;
    }

    l.blocksEnd = at;
    while (at + 4 <= b.size() && bytes::load<uint32_t>(std::span{ b }, at) == format::FRAME_MAGIC)
    {
        const auto size = sizeof(format::FrameHeader) + bytes::load<uint32_t>(std::span{ b }, at + 4) + 4;
        l.frames.emplace_back(at, size);
        at += size;
    }

    return l;
}

auto writeVector(const std::filesystem::path& dir, const std::string& name, const Bytes& bytes) -> void
{
    const auto path = dir / (name + ".xicap");
    test::save(path, bytes);
    std::ofstream(dir / (name + ".json"), std::ios::binary) << test::describe(path).dump(2) << '\n';
}

auto capture(const std::filesystem::path& dir, const Metadata& m, const FramePolicy policy, const std::function<void(Writer&)>& body) -> Bytes
{
    const auto path = dir / "tmp.xicap";
    {
        Writer w(path, m, policy);
        body(w);
        w.close();
    }

    auto bytes = test::bytesOf(path);
    std::filesystem::remove(path);
    return bytes;
}

auto example(Writer& w) -> void
{
    for (uint16_t i{ 0 }; i < 3; ++i)
    {
        w.write(test::out(T0 + uint64_t{ 10 } * i, test::gamePacket(0x0DF, 16, i + 1, static_cast<uint8_t>(i))));
    }
}

auto mixed(Writer& w) -> void
{
    using enum PacketDirection;
    const auto zoneIn = test::gamePacket(0x00A, 256, 1, 0x11);
    const auto chat   = test::gamePacket(0x017, 48, 2, 0x41);
    const auto tell   = test::gamePacket(0x0B6, 40, 1, 0x42);
    const auto move   = test::gamePacket(0x015, 32, 2, 0x22);
    const auto odd    = test::gamePacket(0x00D, 10, 3, 0x33); // 10 bytes: the header's size says 8
    const auto search = std::vector<std::byte>(24, std::byte{ 0x0B });
    const auto other  = std::vector<std::byte>{ std::byte{ 1 }, std::byte{ 2 } };

    w.mark(MarkerKind::Login);
    w.write(test::out(T0, zoneIn));
    w.write({ .timestamp = T0 + 5, .direction = ClientToServer, .data = move, .provenance = PacketFlag::Modified | PacketFlag::FirstInChunk });
    w.write(test::out(T0 + 9, chat));
    w.mark(MarkerKind::Note, "cap start \xE6\x88\xA6\xE3\x81\x84");
    w.write(test::out(T0 + 20, tell, ClientToServer));
    // A stub, as captures converted from older formats hold.
    w.copy({ .timestamp = T0 + 20, .flags = PacketFlag::Excluded | PacketFlag::ClientToServer, .channel = 0, .opcode = 0x0B6, .data = std::span{ tell }.first(4), .markers = {} });
    w.write({ .timestamp = T0 + 20, .direction = ServerToClient, .data = search, .channel = 1, .opcode = 0x0B, .provenance = PacketFlag::Injected });
    w.copy({ .timestamp = T0 + 31, .flags = 0x8020 | PacketFlag::Blocked, .channel = 7, .opcode = 0x1234, .data = other, .markers = {} });
    w.write(test::out(T0 + 31, odd));
    w.mark(MarkerKind::Logout);
    w.mark(static_cast<MarkerKind>(9), "unknown kind");
    w.write(test::out(T0 + 5000, move, ClientToServer));
}

// One frame whose plaintext is given, then a trailer.
auto withPlaintext(const Bytes& plain, const uint32_t packets) -> Bytes
{
    auto packed = Bytes(ZSTD_compressBound(plain.size()));
    packed.resize(ZSTD_compress(packed.data(), packed.size(), plain.data(), plain.size(), 3));
    auto       bytes = metadata::encode(test::metadata());
    const auto start = bytes.size();
    bytes::append(bytes, format::FrameHeader{ .magic = format::FRAME_MAGIC, .payloadSize = static_cast<uint32_t>(packed.size()), .plainSize = static_cast<uint32_t>(plain.size()), .packetCount = packets, .markerCount = 0, .baseTimestamp = T0 });
    bytes.insert(bytes.end(), packed.begin(), packed.end());
    bytes::appendCrc(bytes, start);
    const auto trailer = bytes.size();
    bytes::append(bytes, format::Trailer{ .magic = format::TRAILER_MAGIC, .endTimestamp = T0, .packetCount = packets, .crc = 0 });
    fixCrc(bytes, trailer, bytes.size());
    return bytes;
}

} // namespace

auto main(int argc, char** argv) -> int
{
    if (argc != 2)
    {
        std::cerr << "usage: make_vectors <dir>\n";
        return 2;
    }

    const auto dir = std::filesystem::path(argv[1]);

    auto small               = FramePolicy::live();
    small.maxPacketsPerFrame = 3;
    const auto packets       = capture(dir, test::metadata(), small, mixed);
    const auto frames        = layout(packets).frames;
    const auto trailer       = packets.size() - sizeof(format::Trailer);

    writeVector(dir, "5-example", capture(dir, test::metadata(), FramePolicy::live(), example));
    writeVector(dir, "5-empty", capture(dir, test::metadata(), FramePolicy::live(), [](Writer&)
                                        {
                                        }));
    writeVector(dir, "5-packets", packets);

    auto source          = test::metadata();
    source.origin        = Origin::Converted;
    source.serverKind    = ServerKind::Private;
    source.captureAgent  = "mogsafe";
    source.source        = Source{ .format = "captain", .formatVersion = "1.4.2", .skippedRecords = 2, .metadata = { 'v', '=', '1', '\n' } };
    const auto converted = capture(dir, source, FramePolicy::archive(), mixed);
    writeVector(dir, "5-converted", converted);

    writeVector(dir, "5-cut-off", Bytes(packets.begin(), packets.begin() + static_cast<std::ptrdiff_t>(trailer - 10)));

    auto damaged = packets;
    damaged[frames[1].first + sizeof(format::FrameHeader) + 2] ^= 0x40;
    writeVector(dir, "5-bad-frame", damaged);
    writeVector(dir, "5-bad-frame-cut-off", Bytes(damaged.begin(), damaged.begin() + static_cast<std::ptrdiff_t>(trailer)));

    {
        auto       b  = packets;
        const auto at = layout(b).blocksEnd;
        Bytes      block;
        bytes::append(block, format::BlockHeader{ .type = 0x100, .length = 3 });
        block.insert(block.end(), { 'a', 'b', 'c' });
        bytes::appendCrc(block);
        b.insert(b.begin() + static_cast<std::ptrdiff_t>(at), block.begin(), block.end());
        b[11]++;
        fixCrc(b, 0, sizeof(format::Header));
        writeVector(dir, "5-unknown-block", b);
    }

    {
        auto b = packets;
        b.push_back(0);
        writeVector(dir, "5-bytes-after-trailer", b);
    }

    {
        // A second trailer, whose packet count is wrong, after the right one.
        auto b = packets;
        b.insert(b.end(), packets.end() - sizeof(format::Trailer), packets.end());
        put(b, b.size() - 12, bytes::load<uint64_t>(std::span{ b }, b.size() - 12) + 1);
        fixCrc(b, b.size() - sizeof(format::Trailer), b.size());
        writeVector(dir, "5-trailer-twice", b);
    }

    {
        auto b = packets;
        b[60] ^= 1;
        writeVector(dir, "5-bad-header-crc", b);
    }

    {
        auto b = converted;
        b[sizeof(format::Header) + 9] ^= 1;
        writeVector(dir, "5-bad-block-crc", b);
    }

    {
        auto       b     = converted;
        const auto block = layout(b).blocks[0];
        b.insert(b.begin() + static_cast<std::ptrdiff_t>(block.first + block.second), converted.begin() + static_cast<std::ptrdiff_t>(block.first), converted.begin() + static_cast<std::ptrdiff_t>(block.first + block.second));
        b[11]++;
        fixCrc(b, 0, sizeof(format::Header));
        writeVector(dir, "5-second-source", b);
    }

    {
        auto b = packets;
        b[8]   = 4;
        fixCrc(b, 0, sizeof(format::Header));
        writeVector(dir, "5-version-4", b);
    }

    {
        auto b = packets;
        put(b, trailer + 12, bytes::load<uint64_t>(std::span{ b }, trailer + 12) + 1);
        fixCrc(b, trailer, b.size());
        writeVector(dir, "5-trailer-disagrees", b);
    }

    {
        auto       b  = packets;
        const auto at = frames[1].first + offsetof(format::FrameHeader, baseTimestamp);
        put(b, at, T0);
        fixCrc(b, frames[1].first, frames[1].first + frames[1].second);
        writeVector(dir, "5-time-backwards", b);
    }

    {
        // FORMAT.md's example plaintext, but its first deltaMs is 1.
        auto plain = Bytes{ 0x01, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdf, 0x01, 0xdf, 0x01, 0xdf, 0x01, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x30 };
        for (uint8_t i{ 0 }; i < 3; ++i)
        {
            const auto p = test::gamePacket(0x0DF, 16, 0, i);
            std::ranges::transform(p, std::back_inserter(plain), [](std::byte b)
                                   {
                                       return static_cast<uint8_t>(b);
                                   });
        }

        writeVector(dir, "5-bad-plaintext", withPlaintext(plain, 3));
    }

    return 0;
}
