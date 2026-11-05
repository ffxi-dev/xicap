#include "bytes/crc32.h"
#include "bytes/text.h"
#include "metadata/codec.h"

#include <algorithm>

namespace xicap::metadata
{
namespace
{

auto appendSource(std::vector<uint8_t>& out, const Source& source) -> void
{
    const auto start = out.size();
    bytes::append(out, format::BlockHeader{ .type = format::BLOCK_SOURCE, .length = static_cast<uint32_t>(sizeof(format::SourceHeader) + source.metadata.size()) });
    bytes::append(out, format::SourceHeader{ .format = bytes::toField<16>(source.format), .formatVersion = bytes::toField<16>(source.formatVersion), .skippedRecords = source.skippedRecords });
    out.insert(out.end(), source.metadata.begin(), source.metadata.end());
    bytes::appendCrc(out, start);
}

auto appendBlock(std::vector<uint8_t>& out, const Block& block) -> void
{
    const auto start = out.size();
    bytes::append(out, format::BlockHeader{ .type = block.type, .length = static_cast<uint32_t>(block.payload.size()) });
    out.insert(out.end(), block.payload.begin(), block.payload.end());
    bytes::appendCrc(out, start);
}

} // namespace

auto check(const Metadata& m) -> void
{
    if (m.sourceIndex > m.blocks.size() || std::ranges::any_of(m.blocks, [](const Block& b)
                                                               {
                                                                   return b.type == format::BLOCK_SOURCE;
                                                               }))
    {
        throw Error("xicap: blocks holds a source block, or sourceIndex is past its end");
    }

    if (m.blocks.size() + (m.source ? 1 : 0) > UINT8_MAX)
    {
        throw Error("xicap: more than 255 blocks");
    }

    if (std::ranges::any_of(m.blocks, [](const Block& b)
                            {
                                return b.payload.size() > format::MAX_BLOCK_SIZE;
                            }) ||
        (m.source && m.source->metadata.size() > format::MAX_BLOCK_SIZE - sizeof(format::SourceHeader)))
    {
        throw Error("xicap: block over 16 MiB");
    }
}

auto encode(const Metadata& m) -> std::vector<uint8_t>
{
    check(m);
    const auto header = format::Header{
        .magic             = format::MAGIC,
        .version           = format::VERSION,
        .origin            = m.origin,
        .serverKind        = m.serverKind,
        .blockCount        = static_cast<uint8_t>(m.blocks.size() + (m.source ? 1 : 0)),
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
    for (size_t i{ 0 }; i <= m.blocks.size(); ++i)
    {
        if (m.source && i == m.sourceIndex)
        {
            appendSource(out, *m.source);
        }

        if (i < m.blocks.size())
        {
            appendBlock(out, m.blocks[i]);
        }
    }

    return out;
}

} // namespace xicap::metadata
