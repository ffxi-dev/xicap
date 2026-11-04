#include "xicap/reader.h"
#include "internal/chain.h"
#include "internal/crc32.h"
#include "internal/decoder.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <format>
#include <span>

namespace xicap
{
namespace
{

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

auto textOf(std::span<const char> field) -> std::string
{
    return { field.begin(), std::find(field.begin(), field.end(), '\0') };
}

} // namespace

Reader::Reader(const std::filesystem::path& path, ReaderOptions options)
: options_(options)
, frame_(std::make_unique<internal::DecodedFrame>())
{
    file_.open(path, std::ios::binary);
    if (!file_)
    {
        throw Error(ErrorCode::OpenFailed, "xicap: cannot open " + path.string());
    }
    file_.seekg(0, std::ios::end);
    fileSize_ = static_cast<uint64_t>(file_.tellg());

    readStart();
    decoder_ = std::make_unique<internal::Decoder>(header_.versionMajor, dictionary_);
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

auto Reader::readStart() -> void
{
    std::vector<uint8_t> bytes(HEADER_SIZE);
    if (fileSize_ < HEADER_SIZE || !readAt(file_, 0, bytes))
    {
        throw Error(ErrorCode::ShortHeader, "xicap: short header");
    }
    const auto size = internal::headerSize(bytes);
    if (size > fileSize_)
    {
        throw Error(ErrorCode::ShortHeader, std::format("xicap: header size {} out of range", size));
    }
    bytes.resize(size);
    if (!readAt(file_, 0, bytes))
    {
        throw Error(ErrorCode::ShortHeader, "xicap: short header");
    }
    internal::Start start;
    internal::readHeader(bytes, start);

    uint64_t offset = size;
    for (uint32_t i = 0; i < start.header.extensionCount; ++i)
    {
        std::array<uint8_t, sizeof(ExtensionBlockHeader)> first{};
        if (offset + first.size() > fileSize_ || !readAt(file_, offset, first))
        {
            throw Error(ErrorCode::ShortExtension, "xicap: short extension header");
        }
        const uint64_t blockSize = internal::blockSize(first);
        if (offset + blockSize > fileSize_)
        {
            throw Error(ErrorCode::ShortExtension, "xicap: extension block runs past the file");
        }
        bytes.resize(static_cast<size_t>(blockSize));
        if (!readAt(file_, offset, bytes))
        {
            throw Error(ErrorCode::ShortExtension, "xicap: short extension block");
        }
        internal::readBlock(bytes, i, start);
        offset += blockSize;
    }
    internal::finishBlocks(start);

    header_      = start.header;
    headerBytes_ = std::move(start.headerBytes);
    blockBytes_  = std::move(start.blocks);
    dictionary_  = std::move(start.dictionary);
    policy_      = std::move(start.policy);
    source_      = std::move(start.source);
    extensions_  = std::move(start.extensions);
    dataStart_   = offset;
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
    if (internal::crc32({ reinterpret_cast<const uint8_t*>(&trailer_), offsetof(FooterTrailer, trailerCrc) }) != trailer_.trailerCrc)
    {
        return;
    }
    // Format 3 reserves trailerFlags; format 4 reads an unknown bit as a damaged footer.
    const bool v4     = header_.versionMajor != 3;
    const bool sealed = v4 && (trailer_.trailerFlags & TrailerFlag::Sealed) != 0;
    if (v4 && (trailer_.trailerFlags & ~TrailerFlag::Known) != 0)
    {
        return;
    }
    // Compare by subtraction: a crafted offset must not wrap the sum.
    const uint64_t tail = sizeof(FooterTrailer) + (sealed ? sizeof(SealBlock) : 0);
    if (fileSize_ < dataStart_ + tail)
    {
        return;
    }
    const uint64_t indexBytes = uint64_t{ trailer_.entryCount } * sizeof(FooterIndexEntry);
    const uint64_t indexEnd   = fileSize_ - tail;
    if (trailer_.indexOffset < dataStart_ || trailer_.indexOffset > indexEnd || indexEnd - trailer_.indexOffset != indexBytes ||
        indexBytes > SIZE_MAX)
    {
        return;
    }
    const auto                    indexSize = static_cast<size_t>(indexBytes);
    std::vector<FooterIndexEntry> index(trailer_.entryCount);
    if (!readAt(file_, trailer_.indexOffset, { reinterpret_cast<uint8_t*>(index.data()), indexSize }) ||
        internal::crc32({ reinterpret_cast<const uint8_t*>(index.data()), indexSize }) != trailer_.indexCrc)
    {
        return;
    }
    if (sealed)
    {
        SealBlock seal{};
        if (!readPodAt(file_, indexEnd, seal) || seal.magic != SEAL_MAGIC ||
            internal::crc32({ reinterpret_cast<const uint8_t*>(&seal), offsetof(SealBlock, crc) }) != seal.crc)
        {
            return;
        }
        seal_ = seal;
    }
    indexEntries_  = std::move(index);
    complete_      = true;
    footerDamaged_ = false;
}

auto Reader::readRawFrame(uint64_t offset, uint64_t limit, std::vector<uint8_t>& bytes, internal::FrameInfo& info) -> bool
{
    const auto headerSize = internal::frameHeaderSize(header_.versionMajor);
    if (offset + headerSize + sizeof(uint32_t) > limit)
    {
        return false;
    }
    bytes.resize(headerSize);
    if (!readAt(file_, offset, bytes) || !internal::parseFrameHeader(header_.versionMajor, bytes, info))
    {
        return false;
    }
    const uint64_t size = headerSize + uint64_t{ info.payloadSize } + sizeof(uint32_t);
    if (info.payloadSize > internal::MAX_PAYLOAD_SIZE || offset + size > limit)
    {
        return false;
    }
    bytes.resize(static_cast<size_t>(size));
    if (!readAt(file_, offset, bytes))
    {
        return false;
    }
    uint32_t stored = 0;
    std::memcpy(&stored, bytes.data() + bytes.size() - sizeof(stored), sizeof(stored));
    return internal::crc32({ bytes.data(), bytes.size() - sizeof(stored) }) == stored;
}

auto Reader::resync(uint64_t from, uint64_t limit) -> std::optional<uint64_t>
{
    static constexpr std::array<uint8_t, 4> magic{ 'X', 'C', 'F', 'R' };
    std::vector<uint8_t>                    buf(64 * 1024);
    std::vector<uint8_t>                    candidate;
    internal::FrameInfo                     info;
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
                readRawFrame(pos + i, limit, candidate, info))
            {
                return pos + i;
            }
        }
        pos += n - (magic.size() - 1);
    }
    return std::nullopt;
}

// Adjacent skipped regions are reported as one.
auto Reader::skip(uint64_t offset, uint64_t length) -> void
{
    if (!skipped_.empty())
    {
        auto last = std::prev(skipped_.end());
        if (last->first + last->second == offset)
        {
            last->second += length;
            return;
        }
    }
    skipped_[offset] = length;
}

auto Reader::scanCutOff() -> void
{
    uint64_t            offset = dataStart_;
    internal::FrameInfo info;
    while (offset < fileSize_)
    {
        if (!readRawFrame(offset, fileSize_, raw_, info))
        {
            if (!options_.recovery)
            {
                unreadBytes_ = fileSize_ - offset;
                break;
            }
            const auto next = resync(offset + 1, fileSize_);
            skip(offset, next.value_or(fileSize_) - offset);
            offset = next.value_or(fileSize_);
            continue;
        }
        internal::checkKind(info.kind);
        if (info.kind == FrameKind::Packets)
        {
            indexEntries_.push_back({
                .timestamp  = info.baseTimestamp,
                .fileOffset = offset,
                .zoneId     = info.zoneId,
                .flags      = info.restart() ? IndexFlag::Restart : uint8_t{ 0 },
                .reserved   = {},
            });
        }
        offset += raw_.size();
    }
    endOffset_ = options_.recovery ? fileSize_ : offset;
}

auto Reader::advance() -> bool
{
    frame_->clear();
    packetPos_ = 0;

    internal::FrameInfo info;
    while (true)
    {
        if (const auto it = skipped_.find(nextOffset_); it != skipped_.end())
        {
            nextOffset_ += it->second;
            decoder_->reset();
        }
        if (nextOffset_ >= endOffset_)
        {
            return false;
        }
        const uint64_t offset = nextOffset_;
        if (!readRawFrame(offset, endOffset_, raw_, info))
        {
            if (options_.recovery)
            {
                const auto next = resync(offset + 1, endOffset_);
                skip(offset, next.value_or(endOffset_) - offset);
                nextOffset_ = next.value_or(endOffset_);
                decoder_->reset();
                continue;
            }
            if (complete_)
            {
                throw Error(ErrorCode::CorruptFrame, std::format("xicap: bad frame at offset {}", offset));
            }
            return false;
        }
        const uint64_t size = raw_.size();
        nextOffset_         = offset + size;

        internal::checkKind(info.kind);
        if (info.kind != FrameKind::Packets)
        {
            continue;
        }
        const auto headerSize = internal::frameHeaderSize(header_.versionMajor);
        try
        {
            decoder_->decode(info, { raw_.data() + headerSize, info.payloadSize }, *frame_);
        }
        catch (const Error& error)
        {
            if (error.code() == ErrorCode::UnknownPacketFlag || (complete_ && !options_.recovery))
            {
                throw;
            }
            frame_->clear();
            if (options_.recovery)
            {
                skip(offset, size);
                continue;
            }
            // A cut-off capture ends at its first bad frame.
            endOffset_   = offset;
            unreadBytes_ = fileSize_ - offset;
            return false;
        }
        for (const auto& p : frame_->packets)
        {
            if (internal::namesOtherCharacter(header_, p, { frame_->bytes.data() + p.offset, p.length }))
            {
                characterMismatch_ = true;
            }
        }
        const auto it      = std::ranges::lower_bound(indexEntries_, offset, {}, &FooterIndexEntry::fileOffset);
        currentFrameIndex_ = static_cast<uint64_t>(std::distance(indexEntries_.begin(), it));
        return true;
    }
}

auto Reader::next(ReadPacket& packet) -> bool
{
    while (packetPos_ >= frame_->packets.size())
    {
        if (!advance())
        {
            return false;
        }
    }
    const auto& p    = frame_->packets[packetPos_++];
    packet.timestamp = p.timestamp;
    packet.channel   = p.channel;
    packet.opcode    = p.opcode;
    packet.flags     = p.flags;
    packet.direction = (p.flags & PacketFlag::ClientToServer) ? PacketDirection::ClientToServer : PacketDirection::ServerToClient;
    packet.data      = { reinterpret_cast<const std::byte*>(frame_->bytes.data() + p.offset), p.length };
    packet.markers   = { frame_->markers.data() + p.firstMarker, p.markerCount };
    return true;
}

auto Reader::skipCurrentFrame() noexcept -> void
{
    packetPos_ = frame_->packets.size();
}

auto Reader::reset() -> void
{
    nextOffset_        = dataStart_;
    currentFrameIndex_ = 0;
    frame_->clear();
    packetPos_ = 0;
    decoder_->reset();
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
    // In format 4, decode from the stream's start.
    uint64_t start = frameIndex;
    while (header_.versionMajor != 3 && start > 0 && (indexEntries_[start].flags & IndexFlag::Restart) == 0)
    {
        start--;
    }
    nextOffset_ = indexEntries_[start].fileOffset;
    decoder_->reset();
    while (advance())
    {
        if (currentFrameIndex_ >= frameIndex)
        {
            return SeekResult::Ok;
        }
    }
    return SeekResult::OutOfRange;
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
    while (packetPos_ < frame_->packets.size() && frame_->packets[packetPos_].timestamp < timestamp)
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
    return header_.versionMajor == 3 ? verify3() : verify4();
}

auto Reader::verify3() -> Verification
{
    using internal::checkSignature;
    using internal::signedMessage;
    Verification result{ .key = header_.signingKey };

    internal::Chain chain;
    chain.start(headerBytes_);
    for (const auto& block : blockBytes_)
    {
        chain.absorb(block);
    }

    const uint64_t       limit   = complete_ ? trailer_.indexOffset : fileSize_;
    uint64_t             packets = 0;
    uint64_t             offset  = dataStart_;
    std::vector<uint8_t> frame;
    internal::FrameInfo  info;
    for (; offset < limit;)
    {
        if (!readRawFrame(offset, limit, frame, info))
        {
            if (complete_ && !result.firstFailureOffset)
            {
                result.firstFailureOffset = offset;
            }
            break;
        }
        if (info.kind == FrameKind::Checkpoint && info.payloadSize == sizeof(CheckpointPayload3))
        {
            CheckpointPayload3 checkpoint{};
            std::memcpy(&checkpoint, frame.data() + sizeof(FrameHeader3), sizeof(checkpoint));
            const bool good = checkpoint.chain == chain.value() &&
                              checkSignature(header_.signingKey, checkpoint.signature, signedMessage(internal::CHECKPOINT_PREFIX3, chain.value()));
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
        chain.absorb(frame);
        if (info.kind == FrameKind::Packets)
        {
            packets += info.packetCount;
        }
        offset += frame.size();
    }

    if (complete_ && offset == limit)
    {
        chain.begin();
        chain.update({ reinterpret_cast<const uint8_t*>(indexEntries_.data()), indexEntries_.size() * sizeof(FooterIndexEntry) });
        chain.update({ reinterpret_cast<const uint8_t*>(&trailer_), offsetof(FooterTrailer, signature) });
        chain.end();
        const bool good = checkSignature(header_.signingKey, trailer_.signature, signedMessage(internal::FOOTER_PREFIX3, chain.value()));
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

auto Reader::verify4() -> Verification
{
    using internal::checkSignature;
    using internal::signedMessage;
    Verification result{ .key = header_.signingKey };

    internal::SignedStream stream;
    stream.bytes(headerBytes_);
    for (const auto& block : blockBytes_)
    {
        stream.bytes(block);
    }

    const uint64_t         limit   = complete_ ? trailer_.indexOffset : fileSize_;
    uint64_t               packets = 0;
    uint64_t               offset  = dataStart_;
    std::vector<uint8_t>   frame;
    internal::FrameInfo    info;
    internal::Decoder      decoder(header_.versionMajor, {});
    internal::DecodedFrame decoded;
    const auto             failAt = [&](uint64_t at)
    {
        if (!result.firstFailureOffset)
        {
            result.firstFailureOffset = at;
        }
    };
    for (; offset < limit; offset += frame.size())
    {
        if (!readRawFrame(offset, limit, frame, info))
        {
            if (complete_)
            {
                failAt(offset);
            }
            break;
        }
        internal::checkKind(info.kind);
        const auto payload = std::span{ frame }.subspan(sizeof(FrameHeader), info.payloadSize);
        // Checkpoints sit outside the signed stream, so a bad one is reported but does not stop a later signature
        // from counting.
        if (info.kind == FrameKind::Checkpoint)
        {
            CheckpointPayload checkpoint{};
            if (info.payloadSize == sizeof(CheckpointPayload))
            {
                std::memcpy(&checkpoint, payload.data(), sizeof(checkpoint));
            }
            const bool good = info.payloadSize == sizeof(CheckpointPayload) && checkpoint.packets == packets && checkpoint.digest == stream.digest() &&
                              checkSignature(header_.signingKey, checkpoint.signature, signedMessage(internal::CHECKPOINT_PREFIX, checkpoint.digest));
            if (!good)
            {
                failAt(offset);
                continue;
            }
            result.goodCheckpoints++;
            result.verifiedPackets     = packets;
            result.checkpointDigest    = checkpoint.digest;
            result.checkpointSignature = checkpoint.signature;
        }
        if (info.kind != FrameKind::Packets)
        {
            continue;
        }
        try
        {
            decoder.decode(info, payload, decoded);
        }
        catch (const Error&)
        {
            if (complete_)
            {
                failAt(offset);
            }
            break;
        }
        for (const auto& p : decoded.packets)
        {
            for (size_t m = 0; m < p.markerCount; ++m)
            {
                const auto& marker = decoded.markers[p.firstMarker + m];
                stream.marker(marker.kind, marker.text);
            }
            stream.packet({ .timestamp = p.timestamp, .flags = p.flags, .channel = p.channel, .opcode = p.opcode, .data = { decoded.bytes.data() + p.offset, p.length } });
            packets++;
        }
    }

    if (!complete_ || offset != limit)
    {
        return result;
    }
    const auto end = stream.end(trailer_.totalPacketCount, trailer_.endTimestamp);
    if ((trailer_.trailerFlags & TrailerFlag::EndUnsigned) == 0)
    {
        if (!checkSignature(header_.signingKey, trailer_.signature, signedMessage(internal::FOOTER_PREFIX, end)))
        {
            failAt(trailer_.indexOffset);
        }
        else
        {
            result.signedToEnd     = true;
            result.verifiedPackets = packets;
        }
    }
    if (seal_)
    {
        const auto* bytes = reinterpret_cast<const uint8_t*>(&*seal_);
        result.seal       = SealCheck{
            .key      = seal_->key,
            .agent    = textOf(seal_->agent),
            .sealedAt = seal_->sealedAt,
            .good     = checkSignature(seal_->key, seal_->signature, signedMessage(internal::SEAL_PREFIX, end, std::span{ bytes, offsetof(SealBlock, signature) })),
        };
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
