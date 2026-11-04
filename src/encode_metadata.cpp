#include "crc32.h"
#include "metadata_codec.h"
#include "text.h"

namespace xicap::internal
{
namespace
{

template <typename T>
auto append(std::vector<uint8_t>& out, const T& value) -> void
{
    const auto* p = reinterpret_cast<const uint8_t*>(&value);
    out.insert(out.end(), p, p + sizeof(T));
}

auto appendCrc(std::vector<uint8_t>& out, size_t from) -> void
{
    append(out, crc32(std::span{ out }.subspan(from)));
}

auto appendBlock(std::vector<uint8_t>& out, uint32_t type, const std::vector<uint8_t>& payload) -> void
{
    const auto start = out.size();
    append(out, format::BlockHeader{ .type = type, .length = static_cast<uint32_t>(payload.size()) });
    out.insert(out.end(), payload.begin(), payload.end());
    appendCrc(out, start);
}

auto encodePolicy(const ExclusionPolicy& policy) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    append(out, format::PolicyHeader{ .name = toField<32>(policy.name), .version = policy.version, .ruleCount = static_cast<uint16_t>(policy.rules.size()) });
    for (const auto& rule : policy.rules)
    {
        append(out, format::RuleHeader{
                        .channel    = rule.channel,
                        .direction  = static_cast<uint8_t>(rule.direction),
                        .action     = static_cast<uint8_t>(rule.action),
                        .opcode     = rule.opcode,
                        .rangeCount = static_cast<uint16_t>(rule.ranges.size()),
                    });
        for (const auto& range : rule.ranges)
        {
            append(out, range);
        }
    }

    return out;
}

auto encodeSource(const Source& source) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    append(out, format::SourceHeader{ .format = toField<16>(source.format), .formatVersion = toField<16>(source.formatVersion), .skippedRecords = source.skippedRecords });
    out.insert(out.end(), source.metadata.begin(), source.metadata.end());
    return out;
}

} // namespace

auto encodeMetadata(const Metadata& m) -> std::vector<uint8_t>
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
        .captureAgent      = toField<32>(m.captureAgent),
        .clientVersion     = toField<32>(m.clientVersion),
        .contentId         = m.character.contentId,
        .characterId       = m.character.characterId,
        .characterName     = toField<16>(m.character.name),
        .worldName         = toField<16>(m.character.world),
        .crc               = 0,
    };
    std::vector<uint8_t> out;
    append(out, header);
    out.resize(out.size() - sizeof(header.crc));
    appendCrc(out, 0);
    appendBlock(out, format::BLOCK_POLICY, encodePolicy(m.policy));
    if (m.source)
    {
        appendBlock(out, format::BLOCK_SOURCE, encodeSource(*m.source));
    }

    return out;
}

} // namespace xicap::internal
