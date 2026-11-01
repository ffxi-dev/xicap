#pragma once

// Reads and edits a capture's bytes below the Reader, to craft damaged files. Shared by the vector generator and the tests.

#include <xicap/xicap.h>

#include "internal/crc32.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
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
    size_t             offset;
    size_t             size;
    xicap::FrameHeader header;
};

// Walks the file the way FORMAT.md describes, independent of Reader.
inline auto framesOf(std::span<const uint8_t> bytes) -> std::vector<FrameRef>
{
    std::vector<FrameRef> out;
    if (bytes.size() < xicap::HEADER_SIZE)
    {
        return out; // nothing written yet
    }
    const auto header = podAt<xicap::Header>(bytes, 0);
    size_t     offset = header.headerSize;
    for (uint32_t i = 0; i < header.extensionCount; ++i)
    {
        offset += sizeof(xicap::ExtensionBlockHeader) + podAt<xicap::ExtensionBlockHeader>(bytes, offset).length + 4;
    }
    while (offset + sizeof(xicap::FrameHeader) <= bytes.size() && podAt<uint32_t>(bytes, offset) == xicap::FRAME_MAGIC)
    {
        const auto frame = podAt<xicap::FrameHeader>(bytes, offset);
        const auto size  = sizeof(xicap::FrameHeader) + frame.payloadSize + 4;
        out.push_back({ offset, size, frame });
        offset += size;
    }
    return out;
}

inline auto footerOffset(std::span<const uint8_t> bytes) -> size_t
{
    return podAt<xicap::FooterTrailer>(bytes, bytes.size() - sizeof(xicap::FooterTrailer)).indexOffset;
}

// A frame header with its payload and CRC.
inline auto frameBytes(const xicap::FrameHeader& header, std::span<const uint8_t> payload) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out(sizeof(header));
    std::memcpy(out.data(), &header, sizeof(header));
    out.insert(out.end(), payload.begin(), payload.end());
    const auto crc = xicap::internal::crc32(out);
    out.resize(out.size() + 4);
    std::memcpy(out.data() + out.size() - 4, &crc, 4);
    return out;
}

// Rewrites a packet frame's decompressed content; the capture must have no dictionary.
inline auto rewriteFrame(std::span<const uint8_t> bytes, const FrameRef& frame, const std::function<void(std::vector<uint8_t>&)>& edit) -> std::vector<uint8_t>
{
    const uint8_t*       payload = bytes.data() + frame.offset + sizeof(xicap::FrameHeader);
    std::vector<uint8_t> content(ZSTD_getFrameContentSize(payload, frame.header.payloadSize));
    ZSTD_decompress(content.data(), content.size(), payload, frame.header.payloadSize);
    edit(content);
    std::vector<uint8_t> compressed(ZSTD_compressBound(content.size()));
    auto*                cctx = ZSTD_createCCtx();
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 1);
    compressed.resize(ZSTD_compress2(cctx, compressed.data(), compressed.size(), content.data(), content.size()));
    ZSTD_freeCCtx(cctx);

    auto header        = frame.header;
    header.payloadSize = static_cast<uint32_t>(compressed.size());
    return frameBytes(header, compressed);
}

} // namespace craft
