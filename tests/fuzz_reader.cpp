// libFuzzer target for whole files: Reader in both modes, verify, seeks, and StreamReader fed in pieces. When the
// first input byte is odd, the harness first rewrites every CRC it can find, so mutations reach past the checksums.
// Reader and StreamReader must yield the same packets. Build with clang:
//
//   clang++ -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined -Iinclude -Isrc -Ithird_party/monocypher \
//     tests/fuzz_reader.cpp src/*.cpp third_party/monocypher/monocypher.c \
//     third_party/monocypher/optional/monocypher-ed25519.c -lzstd

#include "internal/crc32.h"
#include "xicap/xicap.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace
{

using namespace xicap;

struct Packet
{
    uint64_t             timestamp;
    uint16_t             flags;
    uint8_t              channel;
    uint16_t             opcode;
    std::vector<uint8_t> data;
    std::string          markers;

    auto operator==(const Packet&) const -> bool = default;
};

auto own(const ReadPacket& p) -> Packet
{
    std::string markers;
    for (const auto& m : p.markers)
    {
        markers += std::to_string(static_cast<int>(m.kind)) + ":" + m.text + "|";
    }
    const auto* d = reinterpret_cast<const uint8_t*>(p.data.data());
    return { p.timestamp, p.flags, p.channel, p.opcode, { d, d + p.data.size() }, markers };
}

template <typename T>
auto get(const std::vector<uint8_t>& b, size_t at) -> T
{
    T v{};
    std::memcpy(&v, b.data() + at, sizeof(T));
    return v;
}

auto putCrc(std::vector<uint8_t>& b, size_t from, size_t to) -> void
{
    const auto crc = internal::crc32({ b.data() + from, to - from });
    std::memcpy(b.data() + to, &crc, 4);
}

// Rewrites the CRCs of the header, the blocks, each frame, the index, the seal, and the trailer.
auto fixCrcs(std::vector<uint8_t>& b) -> void
{
    if (b.size() < HEADER_SIZE)
    {
        return;
    }
    const auto headerSize = get<uint16_t>(b, 10);
    if (headerSize < HEADER_SIZE || headerSize > b.size())
    {
        return;
    }
    putCrc(b, 0, headerSize - 4u);
    size_t     at    = headerSize;
    const auto count = get<uint32_t>(b, 12);
    for (uint32_t i = 0; i < count && at + 8 <= b.size(); ++i)
    {
        const uint64_t end = uint64_t{ at } + 8 + get<uint32_t>(b, at + 4);
        if (end + 4 > b.size())
        {
            return;
        }
        putCrc(b, at, static_cast<size_t>(end));
        at = static_cast<size_t>(end) + 4;
    }
    const size_t frameHeader = 32;
    while (at + frameHeader + 4 <= b.size() && std::memcmp(b.data() + at, "XCFR", 4) == 0)
    {
        const uint64_t end = uint64_t{ at } + frameHeader + get<uint32_t>(b, at + 8);
        if (end + 4 > b.size())
        {
            break;
        }
        putCrc(b, at, static_cast<size_t>(end));
        at = static_cast<size_t>(end) + 4;
    }
    if (b.size() >= at + sizeof(FooterTrailer) && std::memcmp(b.data() + b.size() - 4, "XCPF", 4) == 0)
    {
        const size_t trailer = b.size() - sizeof(FooterTrailer);
        const auto   flags   = v3 ? 0u : get<uint32_t>(b, trailer + 16);
        const size_t seal    = (flags & 1) ? sizeof(SealBlock) : 0;
        const auto   entries = uint64_t{ get<uint32_t>(b, trailer + 20) } * sizeof(FooterIndexEntry);
        if (trailer >= seal + entries)
        {
            const uint64_t index = trailer - seal - entries;
            std::memcpy(b.data() + trailer + 24, &index, 8);
            const auto crc = internal::crc32({ b.data() + static_cast<size_t>(index), static_cast<size_t>(entries) });
            std::memcpy(b.data() + trailer + 32, &crc, 4);
            if (seal != 0)
            {
                putCrc(b, trailer - seal, trailer - seal + 156);
            }
        }
        putCrc(b, trailer, trailer + 104);
    }
}

struct Reading
{
    std::vector<Packet> packets;
    bool                threw{ false };
};

auto readFile(const std::string& path, Reading& out, bool& complete) -> void
{
    try
    {
        Reader     r(path);
        ReadPacket p{};
        complete = r.complete();
        while (r.next(p))
        {
            out.packets.push_back(own(p));
        }
        const auto v = r.verify();
        if (v.verifiedPackets > out.packets.size())
        {
            std::fprintf(stderr, "verify covers %llu packets, the reader read %zu\n", static_cast<unsigned long long>(v.verifiedPackets), out.packets.size());
            std::abort();
        }
        for (uint64_t i = 0; i < r.totalFrames(); ++i)
        {
            r.seekToFrame(i);
            r.next(p);
        }
        if (!out.packets.empty())
        {
            r.seekToTime(out.packets[out.packets.size() / 2].timestamp);
            r.next(p);
        }
        r.listZones();
        r.durationMs();
    }
    catch (const Error&)
    {
        out.threw = true;
    }
}

auto streamFile(const std::vector<uint8_t>& b, size_t step, Reading& out) -> void
{
    try
    {
        StreamReader s;
        ReadPacket   p{};
        for (size_t at = 0; at < b.size(); at += step)
        {
            s.push({ b.data() + at, std::min(step, b.size() - at) });
            while (s.next(p))
            {
                out.packets.push_back(own(p));
            }
        }
    }
    catch (const Error&)
    {
        out.threw = true;
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1)
    {
        return 0;
    }
    std::vector<uint8_t> bytes(data + 1, data + size);
    if (data[0] & 1)
    {
        fixCrcs(bytes);
    }
    static const std::string path = "/dev/shm/xicap-fuzz-" + std::to_string(getpid()) + ".xicap";
    {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }

    Reading read;
    bool    complete = false;
    readFile(path, read, complete);

    try
    {
        Reader     r(path, { .recovery = true });
        ReadPacket p{};
        while (r.next(p))
        {
        }
        r.verify();
    }
    catch (const Error&)
    {
    }

    Reading streamed;
    streamFile(bytes, 1 + data[0] / 2 % 97, streamed);
    // A stream reader reads what a reader reads, save where a complete file's bad frame makes the reader refuse it.
    if (!read.threw && !streamed.threw && read.packets != streamed.packets)
    {
        std::fprintf(stderr, "reader read %zu packets, stream reader %zu (complete %d)\n", read.packets.size(), streamed.packets.size(), complete);
        std::abort();
    }
    return 0;
}
