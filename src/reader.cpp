#include "xicap/reader.h"
#include "internal/chain.h"
#include "internal/crc32.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <zstd.h>

namespace xicap
{
namespace
{

inline constexpr uint64_t FRAME_OVERHEAD = sizeof(FrameHeader) + sizeof(uint32_t);
// zstd's output can exceed its input slightly; anything past this is garbage.
inline constexpr uint64_t MAX_PAYLOAD_SIZE = FrameLimits::MAX_CONTENT_SIZE + 1024 * 1024;

auto crcOf(std::span<const uint8_t> bytes) -> uint32_t
{
    internal::Crc32 crc;
    crc.update(bytes);
    return crc.value();
}

auto readAt(std::ifstream& file, uint64_t offset, std::span<uint8_t> out) -> bool
{
    file.clear();
    file.seekg(static_cast<std::streamoff>(offset));
    file.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    return file && static_cast<size_t>(file.gcount()) == out.size();
}

template <typename T>
auto readPodAt(std::ifstream& file, uint64_t offset, T& out) -> bool
{
    return readAt(file, offset, { reinterpret_cast<uint8_t*>(&out), sizeof(T) });
}

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

Reader::Reader(const std::filesystem::path& path, ReaderOptions options)
: options_(options)
, dctx_(ZSTD_createDCtx(), [](ZSTD_DCtx* c) noexcept
        {
            ZSTD_freeDCtx(c);
        })
{
    if (!dctx_)
    {
        throw Error(ErrorCode::ZstdContextFailed, "xicap: ZSTD_createDCtx failed");
    }
    file_.open(path, std::ios::binary);
    if (!file_)
    {
        throw Error(ErrorCode::OpenFailed, "xicap: cannot open " + path.string());
    }
    file_.seekg(0, std::ios::end);
    fileSize_ = static_cast<uint64_t>(file_.tellg());

    readHeader();
    readExtensions();
    readFooter();
    if (complete_)
    {
        endOffset_ = trailer_.indexOffset;
    }
    else
    {
        scanCutOff();
    }
    nextOffset_ = dataStart_;
}

Reader::~Reader() = default;

auto Reader::clientVersion() const -> std::string
{
    return textOf(header_.clientVersion);
}

auto Reader::captureAgent() const -> std::string
{
    return textOf(header_.captureAgent);
}

auto Reader::skippedRegions() const -> std::vector<SkippedRegion>
{
    std::vector<SkippedRegion> out;
    for (const auto& [offset, length] : skipped_)
    {
        out.push_back({ offset, length });
    }
    return out;
}

auto Reader::getExtension(uint32_t type) const noexcept -> const ExtensionBlock*
{
    const auto it = std::ranges::find_if(extensions_, [type](const ExtensionBlock& ext)
                                         {
                                             return ext.type == type;
                                         });
    return it == extensions_.end() ? nullptr : &*it;
}

auto Reader::readHeader() -> void
{
    if (fileSize_ < HEADER_SIZE || !readPodAt(file_, 0, header_))
    {
        throw Error(ErrorCode::ShortHeader, "xicap: short header");
    }
    if (header_.magic != MAGIC)
    {
        throw Error(ErrorCode::BadMagic, "xicap: bad magic");
    }
    if (header_.versionMajor != VERSION_MAJOR)
    {
        throw Error(ErrorCode::UnsupportedVersion,
                    std::format("xicap: unsupported version {} (expected {})", header_.versionMajor, VERSION_MAJOR));
    }
    const uint16_t size = header_.headerSize;
    if (size < HEADER_SIZE || size > HEADER_SIZE_MAX || size > fileSize_)
    {
        throw Error(ErrorCode::ShortHeader, std::format("xicap: header size {} out of range", size));
    }
    headerBytes_.resize(size);
    if (!readAt(file_, 0, headerBytes_))
    {
        throw Error(ErrorCode::ShortHeader, "xicap: short header");
    }
    uint32_t stored = 0;
    std::memcpy(&stored, headerBytes_.data() + size - sizeof(stored), sizeof(stored));
    if (crcOf({ headerBytes_.data(), size - sizeof(stored) }) != stored)
    {
        throw Error(ErrorCode::HeaderChecksumMismatch, "xicap: header crc mismatch");
    }
}

auto Reader::readExtensions() -> void
{
    uint64_t             offset     = header_.headerSize;
    bool                 haveDict   = false;
    bool                 havePolicy = false;
    std::vector<uint8_t> block;

    for (uint32_t i = 0; i < header_.extensionCount; ++i)
    {
        ExtensionBlockHeader hdr{};
        if (offset + sizeof(hdr) > fileSize_ || !readPodAt(file_, offset, hdr))
        {
            throw Error(ErrorCode::ShortExtension, "xicap: short extension header");
        }
        if (hdr.length > FrameLimits::MAX_EXTENSION_SIZE)
        {
            throw Error(ErrorCode::ExtensionTooLarge, "xicap: extension block over 16 MiB");
        }
        const uint64_t blockSize = sizeof(hdr) + uint64_t{ hdr.length } + sizeof(uint32_t);
        if (offset + blockSize > fileSize_)
        {
            throw Error(ErrorCode::ShortExtension, "xicap: extension block runs past the file");
        }
        block.resize(blockSize);
        if (!readAt(file_, offset, block))
        {
            throw Error(ErrorCode::ShortExtension, "xicap: short extension block");
        }
        uint32_t stored = 0;
        std::memcpy(&stored, block.data() + blockSize - sizeof(stored), sizeof(stored));
        if (crcOf({ block.data(), static_cast<size_t>(blockSize) - sizeof(stored) }) != stored)
        {
            throw Error(ErrorCode::ExtensionChecksumMismatch, std::format("xicap: extension block {} crc mismatch", i));
        }
        const std::span<const uint8_t> payload{ block.data() + sizeof(hdr), hdr.length };
        offset += blockSize;

        if (i == 0 && header_.dictionaryId != 0 && hdr.type != EXT_ZSTD_DICT)
        {
            throw Error(ErrorCode::MissingDictionary, "xicap: the header names a dictionary the file does not carry");
        }
        switch (hdr.type)
        {
            case EXT_ZSTD_DICT:
            {
                if (i != 0 || header_.dictionaryId == 0)
                {
                    throw Error(ErrorCode::DictionaryMismatch, "xicap: dictionary block out of place");
                }
                const uint32_t id = ZSTD_getDictID_fromDict(payload.data(), payload.size());
                if (id != header_.dictionaryId)
                {
                    throw Error(ErrorCode::DictionaryMismatch,
                                std::format("xicap: dictionary id {:#010x}, header says {:#010x}", id, header_.dictionaryId));
                }
                const size_t rc = ZSTD_DCtx_loadDictionary(dctx_.get(), payload.data(), payload.size());
                if (ZSTD_isError(rc))
                {
                    throw Error(ErrorCode::DictionaryMismatch, std::string("xicap: zstd load dictionary: ") + ZSTD_getErrorName(rc));
                }
                haveDict = true;
                break;
            }
            case EXT_EXCLUSION_POLICY:
                if (havePolicy)
                {
                    throw Error(ErrorCode::InvalidExtension, "xicap: two exclusion policy blocks");
                }
                policy_    = parsePolicy(payload);
                havePolicy = true;
                break;
            case EXT_SOURCE:
                source_ = parseSource(payload);
                break;
            default:
                extensions_.push_back({ hdr.type, { payload.begin(), payload.end() } });
                break;
        }
    }
    if (header_.dictionaryId != 0 && !haveDict)
    {
        throw Error(ErrorCode::MissingDictionary, "xicap: the header names a dictionary the file does not carry");
    }
    if (!havePolicy)
    {
        throw Error(ErrorCode::MissingPolicy, "xicap: no exclusion policy block");
    }
    dataStart_ = offset;
}

auto Reader::readFooter() -> void
{
    if (fileSize_ < dataStart_ + sizeof(FooterTrailer) ||
        !readPodAt(file_, fileSize_ - sizeof(FooterTrailer), trailer_) ||
        trailer_.magic != FOOTER_MAGIC)
    {
        return;
    }
    footerDamaged_ = true;
    if (crcOf({ reinterpret_cast<const uint8_t*>(&trailer_), offsetof(FooterTrailer, trailerCrc) }) != trailer_.trailerCrc)
    {
        return;
    }
    const uint64_t indexBytes = uint64_t{ trailer_.entryCount } * sizeof(FooterIndexEntry);
    if (trailer_.indexOffset < dataStart_ || trailer_.indexOffset + indexBytes + sizeof(FooterTrailer) != fileSize_ ||
        indexBytes > SIZE_MAX)
    {
        return;
    }
    const auto                    indexSize = static_cast<size_t>(indexBytes);
    std::vector<FooterIndexEntry> index(trailer_.entryCount);
    if (!readAt(file_, trailer_.indexOffset, { reinterpret_cast<uint8_t*>(index.data()), indexSize }) ||
        crcOf({ reinterpret_cast<const uint8_t*>(index.data()), indexSize }) != trailer_.indexCrc)
    {
        return;
    }
    indexEntries_  = std::move(index);
    complete_      = true;
    footerDamaged_ = false;
}

auto Reader::readRawFrame(uint64_t offset, uint64_t limit, RawFrame& out) -> bool
{
    if (offset + FRAME_OVERHEAD > limit || !readPodAt(file_, offset, out.header) || out.header.magic != FRAME_MAGIC)
    {
        return false;
    }
    if (out.header.payloadSize > MAX_PAYLOAD_SIZE || offset + FRAME_OVERHEAD + out.header.payloadSize > limit)
    {
        return false;
    }
    out.payload.resize(out.header.payloadSize);
    if (!readAt(file_, offset + sizeof(FrameHeader), out.payload) ||
        !readPodAt(file_, offset + sizeof(FrameHeader) + out.header.payloadSize, out.crc))
    {
        return false;
    }
    internal::Crc32 crc;
    crc.update({ reinterpret_cast<const uint8_t*>(&out.header), sizeof(FrameHeader) });
    crc.update(out.payload);
    return crc.value() == out.crc;
}

auto Reader::resync(uint64_t from, uint64_t limit) -> std::optional<uint64_t>
{
    static constexpr std::array<uint8_t, 4> magic{ 'X', 'C', 'F', 'R' };
    std::vector<uint8_t>                    buf(64 * 1024);
    RawFrame                                candidate;
    for (uint64_t pos = from; pos + magic.size() <= limit;)
    {
        const auto n = static_cast<size_t>(std::min<uint64_t>(buf.size(), limit - pos));
        if (!readAt(file_, pos, { buf.data(), n }))
        {
            return std::nullopt;
        }
        for (size_t i = 0; i + magic.size() <= n; ++i)
        {
            if (std::equal(magic.begin(), magic.end(), buf.begin() + static_cast<std::ptrdiff_t>(i)) &&
                readRawFrame(pos + i, limit, candidate))
            {
                return pos + i;
            }
        }
        pos += n - (magic.size() - 1);
    }
    return std::nullopt;
}

auto Reader::scanCutOff() -> void
{
    uint64_t offset = dataStart_;
    while (offset < fileSize_)
    {
        if (!readRawFrame(offset, fileSize_, raw_))
        {
            if (!options_.recovery)
            {
                unreadBytes_ = fileSize_ - offset;
                break;
            }
            const auto next  = resync(offset + 1, fileSize_);
            skipped_[offset] = next.value_or(fileSize_) - offset;
            offset           = next.value_or(fileSize_);
            continue;
        }
        const auto kind = raw_.header.kind;
        if (kind == FrameKind::Packets)
        {
            indexEntries_.push_back({
                .timestamp  = raw_.header.baseTimestamp,
                .fileOffset = offset,
                .zoneId     = raw_.header.zoneId,
                .reserved   = {},
            });
        }
        else if (kind != FrameKind::Checkpoint && static_cast<uint8_t>(kind) >= 0x80)
        {
            throw Error(ErrorCode::UnknownFrameKind, std::format("xicap: unknown frame kind {:#04x}", static_cast<uint8_t>(kind)));
        }
        offset += FRAME_OVERHEAD + raw_.header.payloadSize;
    }
    endOffset_ = options_.recovery ? fileSize_ : offset;
}

auto Reader::advance() -> bool
{
    packets_.clear();
    markers_.clear();
    packetPos_ = 0;

    while (true)
    {
        if (const auto it = skipped_.find(nextOffset_); it != skipped_.end())
        {
            nextOffset_ += it->second;
        }
        if (nextOffset_ >= endOffset_)
        {
            return false;
        }
        const uint64_t offset = nextOffset_;
        if (!readRawFrame(offset, endOffset_, raw_))
        {
            if (options_.recovery)
            {
                const auto next  = resync(offset + 1, endOffset_);
                skipped_[offset] = next.value_or(endOffset_) - offset;
                nextOffset_      = next.value_or(endOffset_);
                continue;
            }
            if (complete_)
            {
                throw Error(ErrorCode::CorruptFrame, std::format("xicap: bad frame at offset {}", offset));
            }
            return false;
        }
        const uint64_t size = FRAME_OVERHEAD + raw_.header.payloadSize;
        nextOffset_         = offset + size;

        const auto kind = raw_.header.kind;
        if (kind != FrameKind::Packets)
        {
            if (kind != FrameKind::Checkpoint && static_cast<uint8_t>(kind) >= 0x80)
            {
                throw Error(ErrorCode::UnknownFrameKind, std::format("xicap: unknown frame kind {:#04x}", static_cast<uint8_t>(kind)));
            }
            continue;
        }
        try
        {
            decodeFrame(raw_);
        }
        catch (const Error& error)
        {
            if (error.code() == ErrorCode::UnknownPacketFlag || (complete_ && !options_.recovery))
            {
                throw;
            }
            packets_.clear();
            markers_.clear();
            if (options_.recovery)
            {
                skipped_[offset] = size;
                continue;
            }
            // A cut-off capture ends at its first bad frame.
            endOffset_   = offset;
            unreadBytes_ = fileSize_ - offset;
            return false;
        }
        const auto it      = std::ranges::lower_bound(indexEntries_, offset, {}, &FooterIndexEntry::fileOffset);
        currentFrameIndex_ = static_cast<uint64_t>(std::distance(indexEntries_.begin(), it));
        return true;
    }
}

auto Reader::decodeFrame(const RawFrame& frame) -> void
{
    const auto& header  = frame.header;
    const auto  rawSize = ZSTD_getFrameContentSize(frame.payload.data(), frame.payload.size());
    if (rawSize == ZSTD_CONTENTSIZE_ERROR || rawSize == ZSTD_CONTENTSIZE_UNKNOWN)
    {
        throw Error(ErrorCode::CorruptFrame, "xicap: frame without a zstd content size");
    }
    if (rawSize > FrameLimits::MAX_CONTENT_SIZE)
    {
        throw Error(ErrorCode::CorruptFrame, std::format("xicap: frame content size {} over 16 MiB", rawSize));
    }
    if (ZSTD_findFrameCompressedSize(frame.payload.data(), frame.payload.size()) != frame.payload.size())
    {
        throw Error(ErrorCode::CorruptFrame, "xicap: payload is not exactly one zstd frame");
    }
    const auto size = static_cast<size_t>(rawSize);
    frameData_.resize(size);
    const size_t result = ZSTD_decompressDCtx(dctx_.get(), frameData_.data(), size, frame.payload.data(), frame.payload.size());
    if (ZSTD_isError(result))
    {
        throw Error(ErrorCode::DecompressFailed, std::string("xicap: zstd decompress: ") + ZSTD_getErrorName(result));
    }
    if (result != size || header.packetCount == 0)
    {
        throw Error(ErrorCode::CorruptFrame, "xicap: corrupt frame");
    }

    const std::span<const uint8_t> content{ frameData_.data(), size };
    size_t                         pos       = 0;
    uint64_t                       timestamp = header.baseTimestamp;
    for (uint32_t i = 0; i < header.packetCount; ++i)
    {
        PacketEntry entry{};
        if (!pop(content, pos, entry) || pos + entry.length > size)
        {
            throw Error(ErrorCode::CorruptFrame, "xicap: packet runs past its frame");
        }
        if ((entry.flags & PacketFlag::Required & ~PacketFlag::KnownRequired) != 0)
        {
            throw Error(ErrorCode::UnknownPacketFlag, std::format("xicap: unknown packet flags {:#06x}", entry.flags));
        }
        if (entry.channel == static_cast<uint8_t>(Channel::Game))
        {
            uint16_t firstWord = 0;
            if (entry.length < sizeof(FFXIPacketHeader))
            {
                throw Error(ErrorCode::CorruptFrame, "xicap: game packet under 4 bytes");
            }
            std::memcpy(&firstWord, frameData_.data() + pos, sizeof(firstWord));
            if ((firstWord & 0x1FFU) != entry.opcode)
            {
                throw Error(ErrorCode::CorruptFrame, "xicap: game packet opcode differs from its header");
            }
        }
        timestamp += entry.deltaMs;
        packets_.push_back({ .entry = entry, .timestamp = timestamp, .dataOffset = pos, .firstMarker = 0, .markerCount = 0 });
        pos += entry.length;
    }

    std::vector<std::pair<uint16_t, ReadMarker>> found;
    for (uint16_t i = 0; i < header.markerCount; ++i)
    {
        FrameMarker marker{};
        if (!pop(content, pos, marker) || pos + marker.textLength > size || marker.packetIndex >= header.packetCount)
        {
            throw Error(ErrorCode::CorruptFrame, "xicap: corrupt marker");
        }
        found.push_back({ marker.packetIndex, { marker.kind, std::string(reinterpret_cast<const char*>(frameData_.data() + pos), marker.textLength) } });
        pos += marker.textLength;
    }
    if (pos != size)
    {
        throw Error(ErrorCode::CorruptFrame, "xicap: bytes after the last marker");
    }
    std::ranges::stable_sort(found, {}, &std::pair<uint16_t, ReadMarker>::first);
    for (auto& [index, marker] : found)
    {
        auto& packet = packets_[index];
        if (packet.markerCount == 0)
        {
            packet.firstMarker = markers_.size();
        }
        packet.markerCount++;
        markers_.push_back(std::move(marker));
    }
}

auto Reader::next(ReadPacket& packet) -> bool
{
    while (packetPos_ >= packets_.size())
    {
        if (!advance())
        {
            return false;
        }
    }
    const auto& p    = packets_[packetPos_++];
    packet.timestamp = p.timestamp;
    packet.channel   = p.entry.channel;
    packet.opcode    = p.entry.opcode;
    packet.flags     = p.entry.flags;
    packet.direction = (p.entry.flags & PacketFlag::ClientToServer) ? PacketDirection::ClientToServer : PacketDirection::ServerToClient;
    packet.data      = { reinterpret_cast<const std::byte*>(frameData_.data() + p.dataOffset), p.entry.length };
    packet.markers   = { markers_.data() + p.firstMarker, p.markerCount };
    return true;
}

auto Reader::skipCurrentFrame() noexcept -> void
{
    packetPos_ = packets_.size();
}

auto Reader::reset() -> void
{
    nextOffset_        = dataStart_;
    currentFrameIndex_ = 0;
    packets_.clear();
    markers_.clear();
    packetPos_ = 0;
}

auto Reader::seekToFrame(uint64_t frameIndex) -> SeekResult
{
    if (indexEntries_.empty())
    {
        return SeekResult::EmptyIndex;
    }
    if (frameIndex >= indexEntries_.size())
    {
        return SeekResult::OutOfRange;
    }
    nextOffset_ = indexEntries_[frameIndex].fileOffset;
    return advance() ? SeekResult::Ok : SeekResult::OutOfRange;
}

auto Reader::seekToTime(uint64_t timestamp) -> SeekResult
{
    if (indexEntries_.empty())
    {
        return SeekResult::EmptyIndex;
    }
    // The last frame starting at or before the time.
    auto it = std::ranges::upper_bound(indexEntries_, timestamp, {}, &FooterIndexEntry::timestamp);
    if (it != indexEntries_.begin())
    {
        --it;
    }
    const auto result = seekToFrame(static_cast<uint64_t>(std::distance(indexEntries_.begin(), it)));
    if (result != SeekResult::Ok)
    {
        return result;
    }
    // Leave next() on the first packet at or after the time.
    while (packetPos_ < packets_.size() && packets_[packetPos_].timestamp < timestamp)
    {
        packetPos_++;
    }
    return SeekResult::Ok;
}

auto Reader::seekToZone(uint16_t zoneId) -> SeekResult
{
    if (indexEntries_.empty())
    {
        return SeekResult::EmptyIndex;
    }
    const auto it = std::ranges::find(indexEntries_, zoneId, &FooterIndexEntry::zoneId);
    if (it == indexEntries_.end())
    {
        return SeekResult::NotFound;
    }
    return seekToFrame(static_cast<uint64_t>(std::distance(indexEntries_.begin(), it)));
}

auto Reader::frameTimestamp(uint64_t frameIndex) const -> uint64_t
{
    return frameIndex < indexEntries_.size() ? indexEntries_[frameIndex].timestamp : 0;
}

auto Reader::listZones() const -> std::vector<ZoneEntry>
{
    std::vector<ZoneEntry> zones;
    uint16_t               lastZone = 0;
    for (const auto& entry : indexEntries_)
    {
        if (entry.zoneId != 0 && entry.zoneId != lastZone)
        {
            zones.push_back({ .zoneId = entry.zoneId, .timestamp = entry.timestamp, .fileOffset = entry.fileOffset });
            lastZone = entry.zoneId;
        }
    }
    return zones;
}

auto Reader::durationMs() const -> uint64_t
{
    if (complete_)
    {
        return trailer_.endTimestamp - header_.startTimestamp;
    }
    return indexEntries_.empty() ? 0 : indexEntries_.back().timestamp - header_.startTimestamp;
}

auto Reader::verify() -> Verification
{
    Verification result{ .key = header_.signingKey };

    internal::Chain chain;
    chain.start(headerBytes_);

    std::vector<uint8_t> block;
    uint64_t             offset = header_.headerSize;
    for (uint32_t i = 0; i < header_.extensionCount; ++i)
    {
        ExtensionBlockHeader hdr{};
        readPodAt(file_, offset, hdr);
        block.resize(sizeof(hdr) + uint64_t{ hdr.length } + sizeof(uint32_t));
        readAt(file_, offset, block);
        chain.absorb(block);
        offset += block.size();
    }

    const uint64_t limit   = complete_ ? trailer_.indexOffset : fileSize_;
    uint64_t       packets = 0;
    RawFrame       frame;
    for (offset = dataStart_; offset < limit;)
    {
        if (!readRawFrame(offset, limit, frame))
        {
            if (complete_ && !result.firstFailureOffset)
            {
                result.firstFailureOffset = offset;
            }
            break;
        }
        if (frame.header.kind == FrameKind::Checkpoint && frame.payload.size() == sizeof(CheckpointPayload))
        {
            CheckpointPayload checkpoint{};
            std::memcpy(&checkpoint, frame.payload.data(), sizeof(checkpoint));
            const bool good = checkpoint.chain == chain.value() &&
                              internal::checkSignature(header_.signingKey, checkpoint.signature, internal::CHECKPOINT_PREFIX, chain.value());
            if (!result.firstFailureOffset)
            {
                if (good)
                {
                    result.goodCheckpoints++;
                    result.verifiedPackets = packets;
                }
                else
                {
                    result.firstFailureOffset = offset;
                }
            }
        }
        chain.begin();
        chain.update({ reinterpret_cast<const uint8_t*>(&frame.header), sizeof(FrameHeader) });
        chain.update(frame.payload);
        chain.update({ reinterpret_cast<const uint8_t*>(&frame.crc), sizeof(frame.crc) });
        chain.end();
        if (frame.header.kind == FrameKind::Packets)
        {
            packets += frame.header.packetCount;
        }
        offset += FRAME_OVERHEAD + frame.header.payloadSize;
    }

    if (complete_ && offset == limit)
    {
        chain.begin();
        chain.update({ reinterpret_cast<const uint8_t*>(indexEntries_.data()), indexEntries_.size() * sizeof(FooterIndexEntry) });
        chain.update({ reinterpret_cast<const uint8_t*>(&trailer_), offsetof(FooterTrailer, signature) });
        chain.end();
        const bool good = internal::checkSignature(header_.signingKey, trailer_.signature, internal::FOOTER_PREFIX, chain.value());
        if (!result.firstFailureOffset)
        {
            if (good)
            {
                result.signedToEnd     = true;
                result.verifiedPackets = packets;
            }
            else
            {
                result.firstFailureOffset = trailer_.indexOffset;
            }
        }
    }
    return result;
}

Reader::Iterator::Iterator(Reader* reader)
: reader_(reader)
, atEnd_(false)
{
    ++(*this);
}

auto Reader::Iterator::operator++() -> Iterator&
{
    if (!reader_ || atEnd_)
    {
        return *this;
    }
    if (!reader_->next(current_))
    {
        atEnd_ = true;
    }
    return *this;
}

auto Reader::Iterator::operator++(int) -> Iterator
{
    Iterator tmp = *this;
    ++(*this);
    return tmp;
}

} // namespace xicap
