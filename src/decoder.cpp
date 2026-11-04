#include "internal/decoder.h"
#include "internal/crc32.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <string_view>
#include <utility>
#include <zstd.h>

namespace xicap::internal
{
namespace
{

template <typename T>
auto pop(std::span<const uint8_t> buf, size_t& pos, T& out) -> bool
{
    if (pos + sizeof(T) > buf.size())
    {
        return false;
    }
    std::memcpy(&out, buf.data() + pos, sizeof(T));
    pos += sizeof(T);
    return true;
}

auto textOf(std::span<const char> field) -> std::string
{
    return { field.begin(), std::find(field.begin(), field.end(), '\0') };
}

auto parsePolicy(std::span<const uint8_t> payload) -> ExclusionPolicy
{
    const auto invalid = []
    {
        return Error(ErrorCode::InvalidPolicy, "xicap: malformed exclusion policy block");
    };
    size_t                pos = 0;
    ExclusionPolicyHeader header{};
    if (!pop(payload, pos, header))
    {
        throw invalid();
    }
    ExclusionPolicy policy{ .name = textOf(header.name), .version = header.version, .rules = {} };
    for (uint16_t i = 0; i < header.ruleCount; ++i)
    {
        ExclusionRuleHeader rule{};
        if (!pop(payload, pos, rule))
        {
            throw invalid();
        }
        ExclusionRule out{
            .channel   = rule.channel,
            .direction = static_cast<ExclusionDirection>(rule.direction),
            .action    = static_cast<ExclusionAction>(rule.action),
            .opcode    = rule.opcode,
            .ranges    = {},
        };
        for (uint16_t r = 0; r < rule.rangeCount; ++r)
        {
            ByteRange range{};
            if (!pop(payload, pos, range))
            {
                throw invalid();
            }
            out.ranges.push_back(range);
        }
        policy.rules.push_back(std::move(out));
    }
    if (pos != payload.size())
    {
        throw invalid();
    }
    return policy;
}

auto parseSource(std::span<const uint8_t> payload) -> SourceInfo
{
    size_t       pos = 0;
    SourceHeader header{};
    if (!pop(payload, pos, header) || payload.size() - pos != header.metadataLength)
    {
        throw Error(ErrorCode::InvalidExtension, "xicap: malformed source block");
    }
    return {
        .format           = textOf(header.format),
        .formatVersion    = textOf(header.formatVersion),
        .skippedRecords   = header.skippedRecords,
        .utcOffsetSeconds = header.utcOffsetSeconds,
        .sourceHash       = header.sourceHash,
        .metadata         = { payload.begin() + static_cast<std::ptrdiff_t>(pos), payload.end() },
    };
}

} // namespace

auto parseFrameHeader(std::span<const uint8_t> bytes, FrameInfo& out) noexcept -> bool
{
    FrameHeader h{};
    std::memcpy(&h, bytes.data(), sizeof(h));
    out = { .kind = h.kind, .frameFlags = h.frameFlags, .markerCount = h.markerCount, .payloadSize = h.payloadSize, .packetCount = h.packetCount, .baseTimestamp = h.baseTimestamp, .zoneId = h.zoneId, .plainSize = h.plainSize };
    return h.magic == FRAME_MAGIC;
}

auto checkKind(FrameKind kind) -> void
{
    if (kind != FrameKind::Packets && kind != FrameKind::Checkpoint && static_cast<uint8_t>(kind) >= 0x80)
    {
        throw Error(ErrorCode::UnknownFrameKind, std::format("xicap: unknown frame kind {:#04x}", static_cast<uint8_t>(kind)));
    }
}

auto headerSize(std::span<const uint8_t> first) -> uint16_t
{
    Header header{};
    if (first.size() < sizeof(header))
    {
        throw Error(ErrorCode::ShortHeader, "xicap: short header");
    }
    std::memcpy(&header, first.data(), sizeof(header));
    if (header.magic != MAGIC)
    {
        throw Error(ErrorCode::BadMagic, "xicap: bad magic");
    }
    if (header.versionMajor != VERSION_MAJOR)
    {
        throw Error(ErrorCode::UnsupportedVersion, std::format("xicap: unsupported version {} (this library reads {})", header.versionMajor, VERSION_MAJOR));
    }
    if (header.headerSize < HEADER_SIZE || header.headerSize > HEADER_SIZE_MAX)
    {
        throw Error(ErrorCode::ShortHeader, std::format("xicap: header size {} out of range", header.headerSize));
    }
    return header.headerSize;
}

auto readHeader(std::span<const uint8_t> header, Start& start) -> void
{
    uint32_t stored = 0;
    std::memcpy(&stored, header.data() + header.size() - sizeof(stored), sizeof(stored));
    if (crc32(header.first(header.size() - sizeof(stored))) != stored)
    {
        throw Error(ErrorCode::HeaderChecksumMismatch, "xicap: header crc mismatch");
    }
    std::memcpy(&start.header, header.data(), sizeof(Header));
    start.headerBytes.assign(header.begin(), header.end());
    if (start.header.dictionaryId != 0)
    {
        throw Error(ErrorCode::DictionaryMismatch, "xicap: format 4 has no dictionary");
    }
}

auto blockSize(std::span<const uint8_t> first) -> uint64_t
{
    ExtensionBlockHeader hdr{};
    std::memcpy(&hdr, first.data(), sizeof(hdr));
    if (hdr.length > FrameLimits::MAX_EXTENSION_SIZE)
    {
        throw Error(ErrorCode::ExtensionTooLarge, "xicap: extension block over 16 MiB");
    }
    return sizeof(hdr) + uint64_t{ hdr.length } + sizeof(uint32_t);
}

auto readBlock(std::span<const uint8_t> block, uint32_t index, Start& start) -> void
{
    ExtensionBlockHeader hdr{};
    std::memcpy(&hdr, block.data(), sizeof(hdr));
    uint32_t stored = 0;
    std::memcpy(&stored, block.data() + block.size() - sizeof(stored), sizeof(stored));
    if (crc32(block.first(block.size() - sizeof(stored))) != stored)
    {
        throw Error(ErrorCode::ExtensionChecksumMismatch, std::format("xicap: extension block {} crc mismatch", index));
    }
    const auto payload = block.subspan(sizeof(hdr), hdr.length);
    start.blocks.emplace_back(block.begin(), block.end());

    switch (hdr.type)
    {
        case EXT_EXCLUSION_POLICY:
            if (start.havePolicy)
            {
                throw Error(ErrorCode::InvalidExtension, "xicap: two exclusion policy blocks");
            }
            start.policy     = parsePolicy(payload);
            start.havePolicy = true;
            break;
        case EXT_SOURCE:
            if (start.source)
            {
                throw Error(ErrorCode::InvalidExtension, "xicap: two source blocks");
            }
            start.source = parseSource(payload);
            break;
        default:
            start.extensions.push_back({ hdr.type, { payload.begin(), payload.end() } });
            break;
    }
}

auto finishBlocks(Start& start) -> void
{
    if (!start.havePolicy)
    {
        throw Error(ErrorCode::MissingPolicy, "xicap: no exclusion policy block");
    }
}

auto namesOtherCharacter(const Header& header, const DecodedPacket& packet, std::span<const uint8_t> data) -> bool
{
    using namespace FFXIPacket;
    if (packet.channel != static_cast<uint8_t>(Channel::Game) || packet.opcode != LOGIN_ZONE ||
        (packet.flags & (PacketFlag::ClientToServer | PacketFlag::Excluded | PacketFlag::Redacted)) != 0 ||
        data.size() < LOGIN_NAME_OFFSET + LOGIN_NAME_SIZE)
    {
        return false;
    }
    uint32_t uniqueNo = 0;
    std::memcpy(&uniqueNo, data.data() + LOGIN_UNIQUE_NO_OFFSET, sizeof(uniqueNo));
    const auto* name = reinterpret_cast<const char*>(data.data() + LOGIN_NAME_OFFSET);
    const auto& c    = header.character;
    return uniqueNo != c.characterId ||
           std::string_view(name, strnlen(name, LOGIN_NAME_SIZE)) != std::string_view(c.characterName.data(), strnlen(c.characterName.data(), c.characterName.size()));
}

Decoder::Decoder()
: dctx_(ZSTD_createDCtx(), [](ZSTD_DCtx* c) noexcept
        {
            ZSTD_freeDCtx(c);
        })
{
    if (!dctx_)
    {
        throw Error(ErrorCode::ZstdContextFailed, "xicap: ZSTD_createDCtx failed");
    }
    ZSTD_DCtx_setParameter(dctx_.get(), ZSTD_d_windowLogMax, FrameLimits::MAX_WINDOW_LOG);
}

Decoder::~Decoder() = default;

auto Decoder::decode(const FrameInfo& frame, std::span<const uint8_t> payload, DecodedFrame& out) -> void
{
    out.clear();
    // Whatever goes wrong, the stream cannot go on.
    const bool restart = frame.restart();
    if (!restart && !streamOpen_)
    {
        throw Error(ErrorCode::CorruptFrame, "xicap: a frame continues a stream that is not open");
    }
    streamOpen_ = false;
    decodeStream(frame, payload, out);
}

auto Decoder::decodeStream(const FrameInfo& frame, std::span<const uint8_t> payload, DecodedFrame& out) -> void
{
    if (frame.plainSize == 0 || frame.plainSize > FrameLimits::MAX_CONTENT_SIZE)
    {
        throw Error(ErrorCode::CorruptFrame, std::format("xicap: plain size {} out of range", frame.plainSize));
    }
    if (frame.packetCount == 0 || frame.packetCount > FrameLimits::MAX_PACKETS)
    {
        throw Error(ErrorCode::CorruptFrame, std::format("xicap: packet count {} out of range", frame.packetCount));
    }
    if (frame.restart())
    {
        // RFC 8878's frame header: a zstd frame, its descriptor without Frame_Content_Size, Single_Segment, the
        // reserved bit, or a dictionary id, and with Content_Checksum.
        constexpr uint32_t ZSTD_FRAME_MAGIC = 0xFD2FB528;
        uint32_t           magic            = 0;
        if (payload.size() >= 5)
        {
            std::memcpy(&magic, payload.data(), sizeof(magic));
        }
        if (magic != ZSTD_FRAME_MAGIC || (payload[4] & 0xEBU) != 0 || (payload[4] & 0x04U) == 0)
        {
            throw Error(ErrorCode::CorruptFrame, "xicap: a stream that is not a zstd frame without content size or dictionary, with checksum");
        }
        ZSTD_DCtx_reset(dctx_.get(), ZSTD_reset_session_only);
    }
    // One byte more than expected, to catch a payload that decodes to more.
    plain_.resize(size_t{ frame.plainSize } + 1);
    ZSTD_inBuffer  in{ payload.data(), payload.size(), 0 };
    ZSTD_outBuffer outBuf{ plain_.data(), plain_.size(), 0 };
    bool           ended = false;
    while (true)
    {
        const size_t inBefore  = in.pos;
        const size_t outBefore = outBuf.pos;
        const size_t rc        = ZSTD_decompressStream(dctx_.get(), &outBuf, &in);
        if (ZSTD_isError(rc))
        {
            throw Error(ErrorCode::DecompressFailed, std::string("xicap: zstd decompress: ") + ZSTD_getErrorName(rc));
        }
        if (rc == 0)
        {
            ended = true;
            break;
        }
        if (outBuf.pos == outBuf.size || (in.pos == inBefore && outBuf.pos == outBefore))
        {
            break;
        }
    }
    if (in.pos != in.size || outBuf.pos != frame.plainSize)
    {
        throw Error(ErrorCode::CorruptFrame, "xicap: payload does not decode to its plain size");
    }
    if (frame.baseTimestamp < lastTimestamp_)
    {
        throw Error(ErrorCode::CorruptFrame, "xicap: a frame starts before the last packet of the frame before it");
    }
    decodeColumns({ plain_.data(), frame.plainSize }, frame.packetCount, frame.markerCount, frame.baseTimestamp, out);
    lastTimestamp_ = out.packets.back().timestamp;
    streamOpen_    = !ended;
}

} // namespace xicap::internal
