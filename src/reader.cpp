#include "xicap/reader.h"
#include "internal/crc32.h"
#include "xicap/dictionary.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <span>
#include <zstd.h>

namespace xicap
{
namespace
{

template <typename T>
auto readPod(std::ifstream& f, T& out) -> bool
{
    f.read(reinterpret_cast<char*>(&out), sizeof(T));
    return f && static_cast<size_t>(f.gcount()) == sizeof(T);
}

template <typename T>
auto popPod(const std::vector<uint8_t>& buf, size_t& pos) -> T
{
    if (pos + sizeof(T) > buf.size())
    {
        throw Error(ErrorCode::CorruptFrame, "xicap: corrupt frame (truncated read)");
    }
    T v;
    std::memcpy(&v, buf.data() + pos, sizeof(T));
    pos += sizeof(T);
    return v;
}

auto stringFromCharArray(std::span<const char> arr) -> std::string
{
    const auto end = std::find(arr.begin(), arr.end(), '\0');
    return { arr.begin(), end };
}

} // namespace

Reader::Reader(const std::filesystem::path& path)
: dctx_(ZSTD_createDCtx(), [](ZSTD_DCtx* c) noexcept
        {
            ZSTD_freeDCtx(c);
        })
{
    if (!dctx_)
    {
        throw Error(ErrorCode::ZstdContextFailed, "xicap: ZSTD_createDCtx failed");
    }

    ZSTD_DCtx_loadDictionary(dctx_.get(), EMBEDDED_DICTIONARY.data(), EMBEDDED_DICTIONARY.size());

    file_.open(path, std::ios::binary);
    if (!file_)
    {
        throw Error(ErrorCode::OpenFailed, "xicap: cannot open " + path.string());
    }

    file_.seekg(0, std::ios::end);
    fileSize_ = static_cast<uint64_t>(file_.tellg());
    file_.seekg(0);

    readHeader();
    readExtensions();
    dataStartOffset_ = static_cast<uint64_t>(file_.tellg());

    loadIndex();

    file_.clear();
    file_.seekg(static_cast<std::streamoff>(dataStartOffset_));
}

Reader::~Reader() = default;

auto Reader::clientVersion() const -> std::string
{
    return stringFromCharArray(header_.clientVersion);
}

auto Reader::captureAgent() const -> std::string
{
    return stringFromCharArray(header_.captureAgent);
}

auto Reader::startTimestamp() const noexcept -> uint64_t
{
    if (header_.startTimestamp != 0)
    {
        return header_.startTimestamp;
    }
    return indexEntries_.empty() ? 0 : indexEntries_.front().timestamp;
}

auto Reader::getExtension(uint32_t type) const noexcept -> const ExtensionBlock*
{
    const auto it = std::find_if(extensions_.begin(), extensions_.end(), [type](const ExtensionBlock& ext)
                                 {
                                     return ext.type == type;
                                 });
    return it == extensions_.end() ? nullptr : &*it;
}

auto Reader::next(ReadPacket& packet) -> bool
{
    while (framePacketsRemaining_ == 0)
    {
        if (!readNextFrame())
        {
            return false;
        }
    }

    const auto entry = popPod<PacketEntry>(frameData_, frameReadPos_);
    currentTimestamp_ += entry.deltaMs;

    if (frameReadPos_ + entry.length > frameData_.size())
    {
        throw Error(ErrorCode::CorruptFrame, "xicap: corrupt frame (data past end)");
    }

    packet.timestamp = currentTimestamp_;
    packet.opcode    = entry.opcode;
    packet.direction = (entry.flags & PACKET_FLAG_DIRECTION_BIT) ? PacketDirection::ClientToServer
                                                                 : PacketDirection::ServerToClient;
    packet.data      = std::span{ reinterpret_cast<const std::byte*>(frameData_.data() + frameReadPos_),
                             entry.length };

    if (framePacketIndex_ < framePacketMarkers_.size())
    {
        packet.markers = std::span{ framePacketMarkers_[framePacketIndex_] };
    }
    else
    {
        packet.markers = {};
    }

    frameReadPos_ += entry.length;
    framePacketIndex_++;
    framePacketsRemaining_--;
    return true;
}

auto Reader::skipCurrentFrame() noexcept -> void
{
    framePacketsRemaining_ = 0;
    frameReadPos_          = 0;
    framePacketIndex_      = 0;
    framePacketMarkers_.clear();
}

auto Reader::reset() -> void
{
    file_.clear();
    file_.seekg(static_cast<std::streamoff>(dataStartOffset_));
    frameData_.clear();
    framePacketMarkers_.clear();
    frameReadPos_          = 0;
    framePacketsRemaining_ = 0;
    framePacketIndex_      = 0;
    currentTimestamp_      = 0;
    currentFrameIndex_     = 0;
    haveLoadedFrame_       = false;
}

auto Reader::seekToTime(uint64_t timestamp) -> SeekResult
{
    if (indexEntries_.empty())
    {
        return SeekResult::EmptyIndex;
    }

    auto it = std::upper_bound(indexEntries_.begin(), indexEntries_.end(), timestamp, [](uint64_t ts, const FooterIndexEntry& entry)
                               {
                                   return ts < entry.timestamp;
                               });
    if (it != indexEntries_.begin())
    {
        --it;
    }

    if (!loadFrame(it->fileOffset))
    {
        return SeekResult::OutOfRange;
    }
    currentFrameIndex_ = static_cast<uint64_t>(std::distance(indexEntries_.begin(), it));

    while (framePacketsRemaining_ > 0 && currentTimestamp_ < timestamp)
    {
        if (frameReadPos_ + sizeof(PacketEntry) > frameData_.size())
        {
            break;
        }
        PacketEntry entry{};
        std::memcpy(&entry, frameData_.data() + frameReadPos_, sizeof(PacketEntry));

        if (frameReadPos_ + sizeof(PacketEntry) + entry.length > frameData_.size())
        {
            break;
        }
        const uint64_t nextTs = currentTimestamp_ + entry.deltaMs;
        if (nextTs > timestamp)
        {
            break;
        }

        frameReadPos_ += sizeof(PacketEntry) + entry.length;
        currentTimestamp_ = nextTs;
        framePacketIndex_++;
        framePacketsRemaining_--;
    }
    return SeekResult::Ok;
}

auto Reader::seekToZone(uint16_t zoneId) -> SeekResult
{
    if (indexEntries_.empty())
    {
        return SeekResult::EmptyIndex;
    }
    for (size_t i = 0; i < indexEntries_.size(); ++i)
    {
        if (indexEntries_[i].zoneId != zoneId)
        {
            continue;
        }
        if (!loadFrame(indexEntries_[i].fileOffset))
        {
            return SeekResult::OutOfRange;
        }
        currentFrameIndex_ = i;
        return SeekResult::Ok;
    }
    return SeekResult::NotFound;
}

auto Reader::seekToFrame(uint64_t frameIndex) -> SeekResult
{
    if (frameIndex >= indexEntries_.size())
    {
        return SeekResult::OutOfRange;
    }
    if (!loadFrame(indexEntries_[frameIndex].fileOffset))
    {
        return SeekResult::OutOfRange;
    }
    currentFrameIndex_ = frameIndex;
    return SeekResult::Ok;
}

auto Reader::frameTimestamp(uint64_t frameIndex) const -> uint64_t
{
    if (frameIndex >= indexEntries_.size())
    {
        return 0;
    }
    return indexEntries_[frameIndex].timestamp;
}

auto Reader::listZones() const -> std::vector<ZoneEntry>
{
    std::vector<ZoneEntry> zones;
    uint16_t               lastZone = 0;
    for (const auto& entry : indexEntries_)
    {
        if (entry.zoneId != 0 && entry.zoneId != lastZone)
        {
            zones.push_back({ .zoneId     = entry.zoneId,
                              .timestamp  = entry.timestamp,
                              .fileOffset = entry.fileOffset });
            lastZone = entry.zoneId;
        }
    }
    return zones;
}

auto Reader::durationMs() const -> uint64_t
{
    if (indexEntries_.empty())
    {
        return 0;
    }
    return indexEntries_.back().timestamp - startTimestamp();
}

auto Reader::readHeader() -> void
{
    if (!readPod(file_, header_))
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
                    std::format("xicap: unsupported version {} (expected {})",
                                header_.versionMajor,
                                VERSION_MAJOR));
    }
    const uint32_t buildDictId = ZSTD_getDictID_fromDict(EMBEDDED_DICTIONARY.data(), EMBEDDED_DICTIONARY.size());
    if (header_.dictionaryId != buildDictId)
    {
        throw Error(ErrorCode::DictionaryMismatch,
                    std::format("xicap: dictionary id mismatch (capture {:#010x}, build {:#010x})",
                                header_.dictionaryId,
                                buildDictId));
    }
}

auto Reader::readExtensions() -> void
{
    extensions_.clear();
    extensions_.reserve(header_.extensionCount);

    for (uint32_t i = 0; i < header_.extensionCount; ++i)
    {
        ExtensionBlockHeader hdr{};
        if (!readPod(file_, hdr))
        {
            throw Error(ErrorCode::ShortExtension, "xicap: short extension header");
        }

        const uint64_t pos       = static_cast<uint64_t>(file_.tellg());
        const uint64_t remaining = pos < fileSize_ ? fileSize_ - pos : 0;
        if (hdr.length > remaining)
        {
            throw Error(ErrorCode::ShortExtension, "xicap: extension length exceeds file");
        }

        ExtensionBlock block;
        block.type = hdr.type;
        block.data.resize(hdr.length);
        if (hdr.length > 0)
        {
            file_.read(reinterpret_cast<char*>(block.data.data()), hdr.length);
            if (!file_)
            {
                throw Error(ErrorCode::ShortExtension, "xicap: short extension data");
            }
        }
        extensions_.push_back(std::move(block));
    }
}

auto Reader::loadIndex() -> void
{
    indexEntries_.clear();
    if (tryReadFooter())
    {
        hasFooter_ = true;
        return;
    }
    scanFramesForIndex();
}

auto Reader::tryReadFooter() -> bool
{
    if (fileSize_ < dataStartOffset_ + sizeof(FooterTrailer))
    {
        return false;
    }

    file_.clear();
    file_.seekg(static_cast<std::streamoff>(fileSize_ - sizeof(FooterTrailer)));

    FooterTrailer trailer{};
    if (!readPod(file_, trailer) || trailer.magic != FOOTER_MAGIC)
    {
        return false;
    }

    const uint64_t indexBytes = static_cast<uint64_t>(trailer.entryCount) * sizeof(FooterIndexEntry);
    if (trailer.indexOffset < dataStartOffset_ ||
        trailer.indexOffset + indexBytes + sizeof(FooterTrailer) != fileSize_)
    {
        return false;
    }

    file_.seekg(static_cast<std::streamoff>(trailer.indexOffset));
    indexEntries_.resize(trailer.entryCount);
    if (trailer.entryCount > 0)
    {
        file_.read(reinterpret_cast<char*>(indexEntries_.data()), static_cast<std::streamsize>(indexBytes));
        if (!file_)
        {
            indexEntries_.clear();
            return false;
        }
    }
    return true;
}

auto Reader::readFrameHeader(FrameHeader& out) -> bool
{
    const auto frameStart = static_cast<uint64_t>(file_.tellg());
    if (!readPod(file_, out))
    {
        return false;
    }
    // Header + compressed payload + 4-byte CRC must fit.
    const uint64_t needed = sizeof(FrameHeader) + out.compressedSize + sizeof(uint32_t);
    return frameStart + needed <= fileSize_;
}

auto Reader::scanFramesForIndex() -> void
{
    file_.clear();
    file_.seekg(static_cast<std::streamoff>(dataStartOffset_));

    while (file_)
    {
        const auto  frameOffset = static_cast<uint64_t>(file_.tellg());
        FrameHeader frameHeader{};
        if (!readFrameHeader(frameHeader))
        {
            break;
        }
        // Skip compressed payload + CRC32 trailer.
        file_.seekg(static_cast<std::streamoff>(frameHeader.compressedSize + sizeof(uint32_t)),
                    std::ios::cur);
        indexEntries_.push_back({
            .timestamp  = frameHeader.baseTimestamp,
            .fileOffset = frameOffset,
            .zoneId     = frameHeader.zoneId,
            .reserved   = {},
        });
    }
    file_.clear();
}

auto Reader::loadFrame(uint64_t offset) -> bool
{
    file_.clear();
    file_.seekg(static_cast<std::streamoff>(offset));
    return readNextFrame();
}

auto Reader::readNextFrame() -> bool
{
    FrameHeader frameHeader{};
    if (!readFrameHeader(frameHeader))
    {
        return false;
    }

    if (compressedBuffer_.size() < frameHeader.compressedSize)
    {
        compressedBuffer_.resize(frameHeader.compressedSize);
    }
    file_.read(reinterpret_cast<char*>(compressedBuffer_.data()), frameHeader.compressedSize);
    if (!file_ || static_cast<size_t>(file_.gcount()) != frameHeader.compressedSize)
    {
        return false;
    }

    uint32_t storedCrc = 0;
    if (!readPod(file_, storedCrc))
    {
        return false;
    }

    internal::Crc32 crc;
    crc.update({ reinterpret_cast<const uint8_t*>(&frameHeader), sizeof(frameHeader) });
    crc.update({ compressedBuffer_.data(), frameHeader.compressedSize });
    if (crc.value() != storedCrc)
    {
        throw Error(ErrorCode::FrameChecksumMismatch,
                    std::format("xicap: frame crc mismatch (stored {:#010x}, computed {:#010x})",
                                storedCrc,
                                crc.value()));
    }

    // ZSTD_getFrameContentSize returns unsigned long long; the sentinels are
    // 64-bit. Compare before narrowing so 32-bit size_t targets (wasm) don't
    // produce always-false comparisons.
    const auto rawSize = ZSTD_getFrameContentSize(compressedBuffer_.data(), frameHeader.compressedSize);
    if (rawSize == ZSTD_CONTENTSIZE_ERROR || rawSize == ZSTD_CONTENTSIZE_UNKNOWN)
    {
        throw Error(ErrorCode::CorruptFrame, "xicap: frame missing content size");
    }
    const size_t reportedSize = static_cast<size_t>(rawSize);

    if (frameData_.size() < reportedSize)
    {
        frameData_.resize(reportedSize);
    }
    const size_t result = ZSTD_decompressDCtx(dctx_.get(), frameData_.data(), reportedSize, compressedBuffer_.data(), frameHeader.compressedSize);
    if (ZSTD_isError(result))
    {
        throw Error(ErrorCode::DecompressFailed,
                    std::string("xicap: zstd decompress: ") + ZSTD_getErrorName(result));
    }
    if (result != reportedSize)
    {
        throw Error(ErrorCode::CorruptFrame, "xicap: decompressed size mismatch");
    }

    if (haveLoadedFrame_)
    {
        currentFrameIndex_++;
    }
    haveLoadedFrame_ = true;

    frameReadPos_          = 0;
    framePacketsRemaining_ = frameHeader.packetCount;
    framePacketIndex_      = 0;
    currentTimestamp_      = frameHeader.baseTimestamp;

    framePacketMarkers_.assign(frameHeader.packetCount, {});
    if (frameHeader.markerCount == 0)
    {
        return true;
    }

    // Markers follow the last packet's data — walk past every entry first.
    size_t pos = 0;
    for (uint32_t i = 0; i < frameHeader.packetCount; ++i)
    {
        if (pos + sizeof(PacketEntry) > result)
        {
            break;
        }
        PacketEntry entry{};
        std::memcpy(&entry, frameData_.data() + pos, sizeof(PacketEntry));
        pos += sizeof(PacketEntry) + entry.length;
    }

    for (uint16_t i = 0; i < frameHeader.markerCount; ++i)
    {
        if (pos + sizeof(FrameMarker) > result)
        {
            break;
        }
        FrameMarker fm{};
        std::memcpy(&fm, frameData_.data() + pos, sizeof(FrameMarker));
        pos += sizeof(FrameMarker);

        std::string text;
        if (fm.textLength > 0 && pos + fm.textLength <= result)
        {
            text.assign(reinterpret_cast<const char*>(frameData_.data() + pos), fm.textLength);
            pos += fm.textLength;
        }
        if (fm.packetIndex < framePacketMarkers_.size())
        {
            framePacketMarkers_[fm.packetIndex].push_back({ std::move(text) });
        }
    }
    return true;
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
