#include "bytes/crc32.h"
#include "bytes/text.h"
#include "metadata/codec.h"

namespace xicap::metadata
{
namespace
{

auto appendBlock(std::vector<uint8_t>& out, uint32_t type, const std::vector<uint8_t>& payload) -> void
{
    const auto start = out.size();
    bytes::append(out, format::BlockHeader{ .type = type, .length = static_cast<uint32_t>(payload.size()) });
    out.insert(out.end(), payload.begin(), payload.end());
    bytes::appendCrc(out, start);
}

auto encodePolicy(const ExclusionPolicy& policy) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    bytes::append(out, format::PolicyHeader{ .name = bytes::toField<32>(policy.name), .version = policy.version, .ruleCount = static_cast<uint16_t>(policy.rules.size()) });
    for (const auto& rule : policy.rules)
    {
        bytes::append(out, format::RuleHeader{
                               .channel    = rule.channel,
                               .direction  = static_cast<uint8_t>(rule.direction),
                               .action     = static_cast<uint8_t>(rule.action),
                               .opcode     = rule.opcode,
                               .rangeCount = static_cast<uint16_t>(rule.ranges.size()),
                           });
        for (const auto& range : rule.ranges)
        {
            bytes::append(out, range);
        }
    }

    return out;
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
        .network           = m.network,
        .blockCount        = static_cast<uint8_t>(1 + static_cast<int>(m.source.has_value())),
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
    appendBlock(out, format::BLOCK_POLICY, encodePolicy(m.policy));
    if (m.source)
    {
        appendBlock(out, format::BLOCK_SOURCE, encodeSource(*m.source));
    }

    return out;
}

} // namespace xicap::metadata
