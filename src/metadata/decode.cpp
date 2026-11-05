#include "bytes/crc32.h"
#include "bytes/text.h"
#include "metadata/codec.h"

#include <format>

namespace xicap::metadata
{
namespace
{

auto readSource(const std::span<const uint8_t> payload) -> Source
{
    if (payload.size() < sizeof(format::SourceHeader))
    {
        throw Error("xicap: malformed source block");
    }

    const auto header   = bytes::load<format::SourceHeader>(payload);
    const auto metadata = payload.subspan(sizeof(header));
    return {
        .format         = bytes::fromField(header.format),
        .formatVersion  = bytes::fromField(header.formatVersion),
        .skippedRecords = header.skippedRecords,
        .metadata       = { metadata.begin(), metadata.end() },
    };
}

} // namespace

auto readHeader(const std::span<const uint8_t> bytes, Metadata& out) -> uint8_t
{
    const auto h = bytes::load<format::Header>(bytes);
    if (h.magic != format::MAGIC)
    {
        throw Error("xicap: not a capture");
    }

    if (h.version != format::VERSION)
    {
        throw Error(std::format("xicap: format {}; this library reads format {} only", h.version, format::VERSION));
    }

    if (!bytes::endsWithCrc(bytes.first(sizeof(h))))
    {
        throw Error("xicap: header CRC mismatch");
    }

    out = Metadata{
        .captureId         = h.captureId,
        .previousCaptureId = h.previousCaptureId,
        .startTimestamp    = h.startTimestamp,
        .origin            = h.origin,
        .serverKind        = h.serverKind,
        .captureAgent      = bytes::fromField(h.captureAgent),
        .clientVersion     = bytes::fromField(h.clientVersion),
        .character         = { .contentId = h.contentId, .characterId = h.characterId, .name = bytes::fromField(h.characterName), .world = bytes::fromField(h.worldName) },
        .source            = {},
    };
    return h.blockCount;
}

auto blockSize(const std::span<const uint8_t> first) -> uint64_t
{
    const auto h = bytes::load<format::BlockHeader>(first);
    if (h.length > format::MAX_BLOCK_SIZE)
    {
        throw Error("xicap: block over 16 MiB");
    }

    return sizeof(h) + uint64_t{ h.length } + sizeof(uint32_t);
}

auto readBlock(const std::span<const uint8_t> block, Metadata& out) -> uint32_t
{
    if (!bytes::endsWithCrc(block))
    {
        throw Error("xicap: block CRC mismatch");
    }

    const auto h       = bytes::load<format::BlockHeader>(block);
    const auto payload = block.subspan(sizeof(h), h.length);
    if (h.type == format::BLOCK_SOURCE)
    {
        out.source = readSource(payload);
    }

    return h.type;
}

} // namespace xicap::metadata
