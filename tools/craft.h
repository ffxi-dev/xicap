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
#include <vector>
#include <zstd.h>

namespace craft
{

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

// A format-4 packet frame's plaintext. The frame must be a whole stream: restart bit set, stream ended.
inline auto plainOf(std::span<const uint8_t> bytes, const FrameRef& frame) -> std::vector<uint8_t>
{
    std::vector<uint8_t> plain(frame.info.plainSize);
    ZSTD_decompress(plain.data(), plain.size(), bytes.data() + frame.offset + sizeof(xicap::FrameHeader), frame.info.payloadSize);
    return plain;
}

// A format-4 packet frame that holds plain as a whole stream, with header's other fields.
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
