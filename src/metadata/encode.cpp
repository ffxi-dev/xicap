#include "bytes/crc32.h"
#include "bytes/text.h"
#include "metadata/codec.h"

#include <algorithm>

namespace xicap::metadata
{
namespace
{

auto appendBlock(std::vector<uint8_t>& out, const Block& block) -> void
{
    const auto start = out.size();
    bytes::append(out, format::BlockHeader{ .type = block.type, .length = static_cast<uint32_t>(block.payload.size()) });
    out.insert(out.end(), block.payload.begin(), block.payload.end());
    bytes::appendCrc(out, start);
}

auto encodeSource(const Source& source) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    bytes::append(out, format::SourceHeader{ .format = bytes::toField<16>(source.format), .formatVersion = bytes::toField<16>(source.formatVersion), .skippedRecords = source.skippedRecords });
    out.insert(out.end(), source.metadata.begin(), source.metadata.end());
    return out;
}

auto written(const Metadata& m) -> std::vector<Block>
{
    if (m.sourceIndex > m.blocks.size() || std::ranges::any_of(m.blocks, [](const Block& b)
                                                               {
                                                                   return b.type == format::BLOCK_SOURCE;
                                                               }))
    {
        throw Error("xicap: blocks holds a source block, or sourceIndex is past its end");
    }

    auto out = m.blocks;
    if (m.source)
    {
        out.insert(out.begin() + static_cast<std::ptrdiff_t>(m.sourceIndex), { .type = format::BLOCK_SOURCE, .payload = encodeSource(*m.source) });
    }

    if (out.size() > UINT8_MAX)
    {
        throw Error("xicap: more than 255 blocks");
    }

    if (std::ranges::any_of(out, [](const Block& b)
                            {
                                return b.payload.size() > format::MAX_BLOCK_SIZE;
                            }))
    {
        throw Error("xicap: block over 16 MiB");
    }

    return out;
}

} // namespace

auto check(const Metadata& metadata) -> void
{
    static_cast<void>(written(metadata));
}

auto encode(const Metadata& m) -> std::vector<uint8_t>
{
    const auto blocks = written(m);
    const auto header = format::Header{
        .magic             = format::MAGIC,
        .version           = format::VERSION,
        .origin            = m.origin,
        .serverKind        = m.serverKind,
        .blockCount        = static_cast<uint8_t>(blocks.size()),
        .captureId         = m.captureId,
        .previousCaptureId = m.previousCaptureId,
        .startTimestamp    = m.startTimestamp,
        .captureAgent      = bytes::toField<32>(m.captureAgent),
        .clientVersion     = bytes::toField<32>(m.clientVersion),
        .contentId         = m.character.contentId,
        .characterId       = m.character.characterId,
        .characterName     = bytes::toField<16>(m.character.name),
        .worldName         = bytes::toField<16>(m.character.world),
        .crc               = 0,
    };
    std::vector<uint8_t> out;
    bytes::append(out, header);
    out.resize(out.size() - sizeof(header.crc));
    bytes::appendCrc(out);
    for (const auto& b : blocks)
    {
        appendBlock(out, b);
    }

    return out;
}

} // namespace xicap::metadata
