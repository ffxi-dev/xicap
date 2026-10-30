#include "xicap/writer.h"
#include "internal/crc32.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <stdexcept>
#include <utility>
#include <zstd.h>

namespace xicap
{
namespace
{

inline constexpr size_t WRITE_BUFFER_BYTES = 256 * 1024;
inline constexpr size_t MARKER_TEXT_MAX    = 1024;

#pragma pack(push, 1)
// FFXI GP_SERV_LOGIN (0x000A) — only the leading prefix up to ZoneNo is needed
// for zone extraction. The full struct lives in the game client.
struct LoginZonePrefix
{
    uint16_t idAndSize;
    uint16_t sync;
    uint8_t  posHead[44];
    uint32_t ZoneNo;
};
static_assert(sizeof(LoginZonePrefix) == 52);
#pragma pack(pop)

template <typename T>
auto writePod(std::ofstream& f, const T& v) -> void
{
    f.write(reinterpret_cast<const char*>(&v), sizeof(T));
}

auto writeBytes(std::ofstream& f, std::span<const uint8_t> bytes) -> void
{
    f.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

template <typename T>
auto appendBytes(std::vector<uint8_t>& dst, const T& value) -> void
{
    const auto* p = reinterpret_cast<const uint8_t*>(&value);
    dst.insert(dst.end(), p, p + sizeof(T));
}

auto appendBytes(std::vector<uint8_t>& dst, std::span<const std::byte> bytes) -> void
{
    const auto* p = reinterpret_cast<const uint8_t*>(bytes.data());
    dst.insert(dst.end(), p, p + bytes.size());
}

auto copyTruncated(std::string_view src, std::span<char> dst) -> void
{
    const auto n = std::min(src.size(), dst.size() - 1);
    std::copy_n(src.begin(), n, dst.begin());
}

auto defaultZoneExtractor(std::span<const std::byte> data) -> uint16_t
{
    if (data.size() < sizeof(LoginZonePrefix))
    {
        return 0;
    }
    LoginZonePrefix prefix{};
    std::memcpy(&prefix, data.data(), sizeof(prefix));
    return static_cast<uint16_t>(prefix.ZoneNo);
}

} // namespace

Writer::Writer(const std::filesystem::path& path, WriterConfig config, FramePolicy policy)
: writeBuf_(WRITE_BUFFER_BYTES)
, config_(std::move(config))
, policy_(policy)
, currentZoneId_(config_.startZoneId)
, cctx_(ZSTD_createCCtx(), [](ZSTD_CCtx* c) noexcept
        {
            ZSTD_freeCCtx(c);
        })
, zoneExtractor_(defaultZoneExtractor)
{
    if (!cctx_)
    {
        throw Error(ErrorCode::ZstdContextFailed, "xicap: ZSTD_createCCtx failed");
    }

    file_.rdbuf()->pubsetbuf(writeBuf_.data(), static_cast<std::streamsize>(writeBuf_.size()));
    file_.open(path, std::ios::binary | std::ios::trunc);
    if (!file_)
    {
        throw Error(ErrorCode::OpenFailed, "xicap: cannot open " + path.string() + " for writing");
    }

    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_compressionLevel, policy_.compressionLevel);
    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_checksumFlag, 1);

    if (!policy_.dictionary.empty())
    {
        dictionary_.assign(policy_.dictionary.begin(), policy_.dictionary.end());
        dictionaryId_ = ZSTD_getDictID_fromDict(dictionary_.data(), dictionary_.size());

        const size_t rc = ZSTD_CCtx_loadDictionary(cctx_.get(), dictionary_.data(), dictionary_.size());
        if (ZSTD_isError(rc))
        {
            throw Error(ErrorCode::ZstdContextFailed,
                        std::string("xicap: zstd load dictionary: ") + ZSTD_getErrorName(rc));
        }
    }

    frameBuffer_.reserve(policy_.maxFrameSize);
    compressedBuffer_.reserve(ZSTD_compressBound(policy_.maxFrameSize));
}

Writer::~Writer()
{
    if (closed_ || !file_.is_open())
    {
        return;
    }
    try
    {
        close();
    }
    catch (...)
    {
        // dtor must not throw; truncated file is recoverable on read.
    }
}

auto Writer::addExtension(uint32_t type, std::span<const std::byte> data) -> void
{
    if (extensionsWritten_)
    {
        throw Error(ErrorCode::AddExtensionAfterPackets,
                    "xicap: cannot add extensions after writing packets");
    }
    const auto* p = reinterpret_cast<const uint8_t*>(data.data());
    extensions_.push_back({ type, std::vector<uint8_t>(p, p + data.size()) });
}

auto Writer::setZoneExtractor(ZoneIdExtractor extractor) -> void
{
    zoneExtractor_ = std::move(extractor);
}

auto Writer::addMarker(std::string_view text) -> void
{
    if (closed_)
    {
        throw Error(ErrorCode::WriterClosed, "xicap: writer is closed");
    }
    if (framePacketCount_ == 0)
    {
        throw Error(ErrorCode::AddMarkerWithoutPacket,
                    "xicap: addMarker requires at least one packet in the current frame");
    }
    text = text.substr(0, std::min(text.size(), MARKER_TEXT_MAX));
    pendingMarkers_.push_back({ static_cast<uint16_t>(framePacketCount_ - 1), std::string(text) });
}

auto Writer::write(uint64_t timestamp, PacketDirection direction, std::span<const std::byte> data) -> void
{
    if (closed_)
    {
        throw Error(ErrorCode::WriterClosed, "xicap: writer is closed");
    }
    if (data.size() > UINT16_MAX)
    {
        // PacketEntry::length is 16-bit; a silent truncation here would corrupt
        // every following packet in the frame.
        throw Error(ErrorCode::PacketTooLarge,
                    std::format("xicap: packet of {} bytes exceeds the {} byte limit", data.size(), UINT16_MAX));
    }

    uint16_t opcode = 0;
    if (data.size() >= sizeof(FFXIPacketHeader))
    {
        // Opcode is the low 9 bits of the first 16-bit word.
        uint16_t firstWord = 0;
        std::memcpy(&firstWord, data.data(), sizeof(firstWord));
        opcode = firstWord & 0x1FFU;

        if (direction == PacketDirection::ServerToClient && opcode == FFXIPacket::LOGIN_ZONE && zoneExtractor_)
        {
            currentZoneId_ = zoneExtractor_(data);
        }
    }

    if (framePacketCount_ == 0)
    {
        frameBaseTimestamp_ = timestamp;
        frameLastTimestamp_ = timestamp;
    }

    if (shouldFlush(timestamp))
    {
        flushFrame();
        frameBaseTimestamp_ = timestamp;
        frameLastTimestamp_ = timestamp;
    }

    uint16_t deltaMs = 0;
    if (framePacketCount_ > 0)
    {
        // shouldFlush ensures the gap fits in uint16_t.
        deltaMs = static_cast<uint16_t>(timestamp - frameLastTimestamp_);
    }
    frameLastTimestamp_ = timestamp;

    const PacketEntry entry{
        .deltaMs = deltaMs,
        .length  = static_cast<uint16_t>(data.size()),
        .opcode  = opcode,
        .flags   = (direction == PacketDirection::ClientToServer) ? PACKET_FLAG_DIRECTION_BIT : uint16_t{ 0 },
    };
    appendBytes(frameBuffer_, entry);
    appendBytes(frameBuffer_, data);

    framePacketCount_++;
    totalPackets_++;
}

auto Writer::flush() -> void
{
    flushFrame();
}

auto Writer::close() -> void
{
    if (closed_)
    {
        return;
    }

    if (!headerWritten_)
    {
        writeHeader();
    }
    if (!extensionsWritten_)
    {
        writeExtensions();
    }
    flushFrame();

    // Back-patch end-of-capture metadata.
    if (totalFrames_ > 0)
    {
        const auto currentPos = file_.tellp();

        file_.seekp(offsetof(Header, endTimestamp));
        writePod(file_, frameLastTimestamp_);

        file_.seekp(offsetof(Header, totalPacketCount));
        writePod(file_, totalPackets_);

        file_.seekp(offsetof(Header, endZoneId));
        writePod(file_, currentZoneId_);

        file_.seekp(currentPos);
    }

    writeFooter();

    file_.close();
    closed_ = true;
}

auto Writer::bytesWritten() -> uint64_t
{
    return static_cast<uint64_t>(file_.tellp());
}

auto Writer::extensionCount() const noexcept -> uint16_t
{
    return static_cast<uint16_t>(extensions_.size() + (dictionary_.empty() ? 0U : 1U));
}

auto Writer::writeHeader() -> void
{
    Header header{
        .magic            = MAGIC,
        .versionMajor     = VERSION_MAJOR,
        .versionMinor     = VERSION_MINOR,
        .captureAgent     = {},
        .extensionCount   = extensionCount(),
        .clientVersion    = {},
        .startZoneId      = config_.startZoneId,
        .startTimestamp   = 0,
        .lobby            = config_.lobby,
        .startWeather     = config_.startWeather,
        .padding0         = 0,
        .dictionaryId     = dictionaryId_,
        .endTimestamp     = 0,
        .totalPacketCount = 0,
        .endZoneId        = 0,
        .reserved         = {},
    };
    copyTruncated(config_.clientVersion, header.clientVersion);
    copyTruncated(config_.captureAgent, header.captureAgent);

    writePod(file_, header);
    headerWritten_ = true;
}

auto Writer::writeExtensions() -> void
{
    if (!headerWritten_)
    {
        writeHeader();
    }

    if (!dictionary_.empty())
    {
        // Written first so a streaming consumer can decode frames as they arrive.
        const ExtensionBlockHeader hdr{
            .type   = EXT_ZSTD_DICT,
            .length = static_cast<uint32_t>(dictionary_.size()),
        };
        writePod(file_, hdr);
        writeBytes(file_, dictionary_);
    }

    for (const auto& ext : extensions_)
    {
        if (ext.data.size() > UINT32_MAX)
        {
            throw Error(ErrorCode::ExtensionTooLarge, "xicap: extension block exceeds 4 GiB");
        }
        const ExtensionBlockHeader hdr{
            .type   = ext.type,
            .length = static_cast<uint32_t>(ext.data.size()),
        };
        writePod(file_, hdr);
        writeBytes(file_, ext.data);
    }
    extensionsWritten_ = true;
}

auto Writer::flushFrame() -> void
{
    if (framePacketCount_ == 0)
    {
        return;
    }
    if (!extensionsWritten_)
    {
        writeExtensions();
    }

    if (totalFrames_ == 0)
    {
        // First frame's base is the capture's start timestamp; back-patch the
        // header field that was zero-initialised.
        const auto currentPos = file_.tellp();
        file_.seekp(offsetof(Header, startTimestamp));
        writePod(file_, frameBaseTimestamp_);
        file_.seekp(currentPos);
    }

    for (const auto& marker : pendingMarkers_)
    {
        const FrameMarker fm{
            .packetIndex = marker.packetIndex,
            .textLength  = static_cast<uint16_t>(marker.text.size()),
        };
        appendBytes(frameBuffer_, fm);
        appendBytes(frameBuffer_, std::as_bytes(std::span{ marker.text }));
    }

    const size_t bound = ZSTD_compressBound(frameBuffer_.size());
    if (compressedBuffer_.size() < bound)
    {
        compressedBuffer_.resize(bound);
    }
    const size_t compressedSize = ZSTD_compress2(cctx_.get(), compressedBuffer_.data(), compressedBuffer_.size(), frameBuffer_.data(), frameBuffer_.size());
    if (ZSTD_isError(compressedSize))
    {
        throw Error(ErrorCode::CompressFailed,
                    std::string("xicap: zstd compress: ") + ZSTD_getErrorName(compressedSize));
    }

    totalUncompressedBytes_ += frameBuffer_.size();
    totalCompressedBytes_ += compressedSize;

    const auto frameOffset = static_cast<uint64_t>(file_.tellp());

    const FrameHeader frameHeader{
        .compressedSize = static_cast<uint32_t>(compressedSize),
        .packetCount    = framePacketCount_,
        .baseTimestamp  = frameBaseTimestamp_,
        .zoneId         = currentZoneId_,
        .markerCount    = static_cast<uint16_t>(pendingMarkers_.size()),
    };

    internal::Crc32 crc;
    crc.update({ reinterpret_cast<const uint8_t*>(&frameHeader), sizeof(frameHeader) });
    crc.update({ compressedBuffer_.data(), compressedSize });
    const uint32_t frameCrc = crc.value();

    writePod(file_, frameHeader);
    writeBytes(file_, std::span{ compressedBuffer_.data(), compressedSize });
    writePod(file_, frameCrc);

    frameIndex_.push_back({
        .timestamp  = frameBaseTimestamp_,
        .fileOffset = frameOffset,
        .zoneId     = currentZoneId_,
        .reserved   = {},
    });

    totalFrames_++;
    frameBuffer_.clear();
    framePacketCount_ = 0;
    pendingMarkers_.clear();
}

auto Writer::writeFooter() -> void
{
    if (frameIndex_.empty())
    {
        return;
    }

    const auto indexOffset = static_cast<uint64_t>(file_.tellp());
    file_.write(reinterpret_cast<const char*>(frameIndex_.data()),
                static_cast<std::streamsize>(frameIndex_.size() * sizeof(FooterIndexEntry)));

    const FooterTrailer trailer{
        .magic       = FOOTER_MAGIC,
        .entryCount  = static_cast<uint32_t>(frameIndex_.size()),
        .indexOffset = indexOffset,
        .reserved    = {},
    };
    writePod(file_, trailer);
    file_.flush();
}

auto Writer::shouldFlush(uint64_t nextTimestamp) const noexcept -> bool
{
    if (framePacketCount_ >= policy_.maxPacketsPerFrame)
    {
        return true;
    }
    if (frameBuffer_.size() >= policy_.maxFrameSize)
    {
        return true;
    }
    if (framePacketCount_ > 0)
    {
        if ((frameLastTimestamp_ - frameBaseTimestamp_) >= policy_.maxFrameTimeMs)
        {
            return true;
        }
        // Force a flush before deltaMs would clip.
        if ((nextTimestamp - frameLastTimestamp_) > UINT16_MAX)
        {
            return true;
        }
    }
    return false;
}

} // namespace xicap
