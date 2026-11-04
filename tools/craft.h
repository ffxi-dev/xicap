#pragma once

// Reads and edits a capture's bytes below the Reader, to craft damaged files. Shared by the vector generator and the tests.

#include <xicap/xicap.h>

#include "internal/crc32.h"
#include "internal/decoder.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <zstd.h>

namespace craft
{

// A game packet: its 4-byte header, then fill.
inline auto gamePacket(uint16_t opcode, size_t size, uint8_t fill = 0xAB, uint16_t sync = 0x1234) -> std::vector<std::byte>
{
    std::vector<std::byte> p(size, std::byte{ fill });
    const auto             words = static_cast<uint16_t>((size / 4) & 0x7F);
    const auto             hdr   = static_cast<uint16_t>((words << 9) | (opcode & 0x1FF));
    p[0]                         = std::byte(hdr & 0xFF);
    p[1]                         = std::byte(hdr >> 8);
    p[2]                         = std::byte(sync & 0xFF);
    p[3]                         = std::byte(sync >> 8);
    return p;
}

// FORMAT.md's example plaintext: three 0x0DF packets to the client, 10 ms apart, with syncs 1, 2, and 3.
inline constexpr std::string_view EXAMPLE_PLAIN = "000a0a"
                                                  "000000"
                                                  "000000"
                                                  "df01df01df01"
                                                  "000000"
                                                  "020202"
                                                  "30"
                                                  "df080000000000000000000000000000"
                                                  "df080000010101010101010101010101"
                                                  "df080000020202020202020202020202";

inline auto fromHex(std::string_view hex) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        out.push_back(static_cast<uint8_t>(std::stoi(std::string(hex.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

inline auto bytesOf(const std::filesystem::path& path) -> std::vector<uint8_t>
{
    std::ifstream f(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(f), {} };
}

inline auto save(const std::filesystem::path& path, std::span<const uint8_t> bytes) -> void
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

template <typename T>
auto podAt(std::span<const uint8_t> bytes, size_t offset) -> T
{
    T v{};
    std::memcpy(&v, bytes.data() + offset, sizeof(T));
    return v;
}

struct FrameRef
{
    size_t                     offset;
    size_t                     size;
    xicap::internal::FrameInfo info;
};

// Walks the file the way FORMAT.md describes, independent of Reader.
inline auto framesOf(std::span<const uint8_t> bytes) -> std::vector<FrameRef>
{
    std::vector<FrameRef> out;
    if (bytes.size() < xicap::HEADER_SIZE)
    {
        return out; // nothing written yet
    }
    const auto header     = podAt<xicap::Header>(bytes, 0);
    const auto headerSize = sizeof(xicap::FrameHeader);
    size_t     offset     = header.headerSize;
    for (uint32_t i = 0; i < header.extensionCount; ++i)
    {
        offset += sizeof(xicap::ExtensionBlockHeader) + podAt<xicap::ExtensionBlockHeader>(bytes, offset).length + 4;
    }
    xicap::internal::FrameInfo info;
    while (offset + headerSize <= bytes.size() && xicap::internal::parseFrameHeader(bytes.subspan(offset), info))
    {
        const auto size = headerSize + info.payloadSize + 4;
        out.push_back({ offset, size, info });
        offset += size;
    }
    return out;
}

inline auto packetFrames(std::span<const uint8_t> bytes) -> std::vector<FrameRef>
{
    std::vector<FrameRef> out;
    for (const auto& f : framesOf(bytes))
    {
        if (f.info.kind == xicap::FrameKind::Packets)
        {
            out.push_back(f);
        }
    }
    return out;
}

inline auto footerOffset(std::span<const uint8_t> bytes) -> size_t
{
    return podAt<xicap::FooterTrailer>(bytes, bytes.size() - sizeof(xicap::FooterTrailer)).indexOffset;
}

// A frame header with its payload and CRC.
template <typename Header>
auto frameBytes(const Header& header, std::span<const uint8_t> payload) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out(sizeof(header));
    std::memcpy(out.data(), &header, sizeof(header));
    out.insert(out.end(), payload.begin(), payload.end());
    const auto crc = xicap::internal::crc32(out);
    out.resize(out.size() + 4);
    std::memcpy(out.data() + out.size() - 4, &crc, 4);
    return out;
}

// A packet frame's plaintext. The frame must be a whole stream: restart bit set, stream ended.
inline auto plainOf(std::span<const uint8_t> bytes, const FrameRef& frame) -> std::vector<uint8_t>
{
    std::vector<uint8_t> plain(frame.info.plainSize);
    ZSTD_decompress(plain.data(), plain.size(), bytes.data() + frame.offset + sizeof(xicap::FrameHeader), frame.info.payloadSize);
    return plain;
}

// A packet frame that holds plain as a whole stream, with header's other fields.
inline auto packetFrame(xicap::FrameHeader header, std::span<const uint8_t> plain) -> std::vector<uint8_t>
{
    std::vector<uint8_t> compressed(ZSTD_compressBound(plain.size()));
    auto*                cctx = ZSTD_createCCtx();
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 1);
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_contentSizeFlag, 0);
    compressed.resize(ZSTD_compress2(cctx, compressed.data(), compressed.size(), plain.data(), plain.size()));
    ZSTD_freeCCtx(cctx);
    header.magic = xicap::FRAME_MAGIC;
    header.frameFlags |= xicap::FrameFlag::Restart;
    header.payloadSize = static_cast<uint32_t>(compressed.size());
    header.plainSize   = static_cast<uint32_t>(plain.size());
    return frameBytes(header, compressed);
}

inline auto splice(const std::vector<uint8_t>& bytes, size_t at, size_t remove, std::span<const uint8_t> insert) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(at));
    out.insert(out.end(), insert.begin(), insert.end());
    out.insert(out.end(), bytes.begin() + static_cast<std::ptrdiff_t>(at + remove), bytes.end());
    return out;
}

} // namespace craft
