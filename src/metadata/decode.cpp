#include "bytes/crc32.h"
#include "bytes/text.h"
#include "metadata/codec.h"

#include <format>

namespace xicap::metadata
{
namespace
{

// The T at pos in a policy block's payload, moving pos past it.
template <typename T>
auto take(std::span<const uint8_t> payload, size_t& pos) -> T
{
    if (payload.size() - pos < sizeof(T))
    {
        throw Error("xicap: malformed exclusion policy block");
    }

    pos += sizeof(T);
    return bytes::load<T>(payload, pos - sizeof(T));
}

auto readPolicy(std::span<const uint8_t> payload) -> ExclusionPolicy
{
    size_t     pos{ 0 };
    const auto header = take<format::PolicyHeader>(payload, pos);
    auto       policy = ExclusionPolicy{ .name = bytes::fromField(header.name), .version = header.version, .rules = {} };
    for (uint16_t i{ 0 }; i < header.ruleCount; ++i)
    {
        const auto rule  = take<format::RuleHeader>(payload, pos);
        auto&      added = policy.rules.emplace_back(ExclusionRule{
            .channel   = rule.channel,
            .direction = static_cast<ExclusionDirection>(rule.direction),
            .action    = static_cast<ExclusionAction>(rule.action),
            .opcode    = rule.opcode,
            .ranges    = {},
        });
        for (uint16_t r{ 0 }; r < rule.rangeCount; ++r)
        {
            added.ranges.push_back(take<ByteRange>(payload, pos));
        }
    }

    if (pos != payload.size())
    {
        throw Error("xicap: malformed exclusion policy block");
    }

    return policy;
}

auto readSource(std::span<const uint8_t> payload) -> Source
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

auto readHeader(std::span<const uint8_t> bytes, Metadata& out) -> uint8_t
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
        .policy            = {},
        .source            = {},
    };
    return h.blockCount;
}

auto blockSize(std::span<const uint8_t> first) -> uint64_t
{
    const auto h = bytes::load<format::BlockHeader>(first);
    if (h.length > format::MAX_BLOCK_SIZE)
    {
        throw Error("xicap: block over 16 MiB");
    }

    return sizeof(h) + uint64_t{ h.length } + sizeof(uint32_t);
}

auto readBlock(std::span<const uint8_t> block, Metadata& out) -> uint32_t
{
    if (!bytes::endsWithCrc(block))
    {
        throw Error("xicap: block CRC mismatch");
    }

    const auto h       = bytes::load<format::BlockHeader>(block);
    const auto payload = block.subspan(sizeof(h), h.length);
    switch (h.type)
    {
        case format::BLOCK_POLICY:
            out.policy = readPolicy(payload);
            break;
        case format::BLOCK_SOURCE:
            out.source = readSource(payload);
            break;
        default:
            break;
    }

    return h.type;
}

} // namespace xicap::metadata
