#include "bytes/crc32.h"
#include "bytes/text.h"
#include "metadata/codec.h"

namespace xicap::metadata
{
namespace
{

auto appendBlock(std::vector<uint8_t>& out, const uint32_t type, const std::vector<uint8_t>& payload) -> void
{
    const auto start = out.size();
    bytes::append(out, format::BlockHeader{ .type = type, .length = static_cast<uint32_t>(payload.size()) });
    out.insert(out.end(), payload.begin(), payload.end());
    bytes::appendCrc(out, start);
}

auto encodeSource(const Source& source) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    bytes::append(out, format::SourceHeader{ .format = bytes::toField<16>(source.format), .formatVersion = bytes::toField<16>(source.formatVersion), .skippedRecords = source.skippedRecords });
    out.insert(out.end(), source.metadata.begin(), source.metadata.end());
    return out;
}

} // namespace

auto encode(const Metadata& m) -> std::vector<uint8_t>
{
    const auto header = format::Header{
        .magic             = format::MAGIC,
        .version           = format::VERSION,
        .origin            = m.origin,
        .serverKind        = m.serverKind,
        .blockCount        = static_cast<uint8_t>(m.source.has_value()),
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
    if (m.source)
    {
        appendBlock(out, format::BLOCK_SOURCE, encodeSource(*m.source));
    }

    return out;
}

} // namespace xicap::metadata
