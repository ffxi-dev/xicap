#include "crc32.h"
#include "metadata_codec.h"
#include "text.h"

#include <cstring>
#include <format>

namespace xicap::internal
{
namespace
{

// Reads a T at pos and moves past it; false when fewer bytes are left.
template <typename T>
auto take(std::span<const uint8_t> bytes, size_t& pos, T& out) -> bool
{
    if (bytes.size() - pos < sizeof(T))
    {
        return false;
    }
    std::memcpy(&out, bytes.data() + pos, sizeof(T));
    pos += sizeof(T);
    return true;
}

auto endsWithCrc(std::span<const uint8_t> bytes) -> bool
{
    uint32_t stored = 0;
    std::memcpy(&stored, bytes.data() + bytes.size() - sizeof(stored), sizeof(stored));
    return crc32(bytes.first(bytes.size() - sizeof(stored))) == stored;
}

auto readPolicy(std::span<const uint8_t> payload) -> ExclusionPolicy
{
    const auto           malformed = Error("xicap: malformed exclusion policy block");
    size_t               pos       = 0;
    format::PolicyHeader header{};
    if (!take(payload, pos, header))
    {
        throw malformed;
    }
    auto policy = ExclusionPolicy{ .name = fromField(header.name), .version = header.version, .rules = {} };
    for (uint16_t i = 0; i < header.ruleCount; ++i)
    {
        format::RuleHeader rule{};
        if (!take(payload, pos, rule))
        {
            throw malformed;
        }
        auto& out = policy.rules.emplace_back(ExclusionRule{
            .channel   = rule.channel,
            .direction = static_cast<ExclusionDirection>(rule.direction),
            .action    = static_cast<ExclusionAction>(rule.action),
            .opcode    = rule.opcode,
            .ranges    = std::vector<ByteRange>(rule.rangeCount),
        });
        for (auto& range : out.ranges)
        {
            if (!take(payload, pos, range))
            {
                throw malformed;
            }
        }
    }
    if (pos != payload.size())
    {
        throw malformed;
    }

    return policy;
}

auto readSource(std::span<const uint8_t> payload) -> Source
{
    size_t               pos = 0;
    format::SourceHeader header{};
    if (!take(payload, pos, header))
    {
        throw Error("xicap: malformed source block");
    }
    return {
        .format         = fromField(header.format),
        .formatVersion  = fromField(header.formatVersion),
        .skippedRecords = header.skippedRecords,
        .metadata       = { payload.begin() + static_cast<std::ptrdiff_t>(pos), payload.end() },
    };
}

} // namespace

auto readHeader(std::span<const uint8_t> bytes, Metadata& out) -> uint8_t
{
    format::Header h{};
    std::memcpy(&h, bytes.data(), sizeof(h));
    if (h.magic != format::MAGIC)
    {
        throw Error("xicap: not a capture");
    }
    if (h.version != format::VERSION)
    {
        throw Error(std::format("xicap: format {}; this library reads format {} only", h.version, format::VERSION));
    }
    if (!endsWithCrc(bytes.first(sizeof(h))))
    {
        throw Error("xicap: header CRC mismatch");
    }
    out = Metadata{
        .captureId         = h.captureId,
        .previousCaptureId = h.previousCaptureId,
        .startTimestamp    = h.startTimestamp,
        .origin            = h.origin,
        .network           = h.network,
        .captureAgent      = fromField(h.captureAgent),
        .clientVersion     = fromField(h.clientVersion),
        .character         = { .contentId = h.contentId, .characterId = h.characterId, .name = fromField(h.characterName), .world = fromField(h.worldName) },
        .policy            = {},
        .source            = {},
    };
    return h.blockCount;
}

auto blockSize(std::span<const uint8_t> first) -> uint64_t
{
    format::BlockHeader h{};
    std::memcpy(&h, first.data(), sizeof(h));
    if (h.length > format::MAX_BLOCK_SIZE)
    {
        throw Error("xicap: block over 16 MiB");
    }
    return sizeof(h) + uint64_t{ h.length } + sizeof(uint32_t);
}

auto readBlock(std::span<const uint8_t> block, Metadata& out) -> uint32_t
{
    if (!endsWithCrc(block))
    {
        throw Error("xicap: block CRC mismatch");
    }
    format::BlockHeader h{};
    std::memcpy(&h, block.data(), sizeof(h));
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

} // namespace xicap::internal
