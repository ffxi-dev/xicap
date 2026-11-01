#include "xicap/writer.h"
#include "internal/chain.h"
#include "internal/crc32.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <random>
#include <utility>
#include <zstd.h>

namespace xicap
{
namespace
{

inline constexpr size_t MARKER_TEXT_MAX = 1024;
// The game channel's stub keeps the 4-byte FFXI header.
inline constexpr size_t GAME_STUB_BYTES = sizeof(FFXIPacketHeader);

template <typename T>
auto appendPod(std::vector<uint8_t>& dst, const T& value) -> void
{
    const auto* p = reinterpret_cast<const uint8_t*>(&value);
    dst.insert(dst.end(), p, p + sizeof(T));
}

auto appendBytes(std::vector<uint8_t>& dst, std::span<const uint8_t> bytes) -> void
{
    dst.insert(dst.end(), bytes.begin(), bytes.end());
}

auto asBytes(std::string_view text) -> std::span<const uint8_t>
{
    return { reinterpret_cast<const uint8_t*>(text.data()), text.size() };
}

auto appendCrc(std::vector<uint8_t>& block) -> void
{
    appendPod(block, internal::crc32(block));
}

// Cuts text to at most maxBytes without splitting a UTF-8 character.
auto cutUtf8(std::string_view text, size_t maxBytes) -> std::string_view
{
    if (text.size() <= maxBytes)
    {
        return text;
    }
    size_t n = maxBytes;
    while (n > 0 && (static_cast<uint8_t>(text[n]) & 0xC0U) == 0x80U)
    {
        --n;
    }
    return text.substr(0, n);
}

auto copyText(std::string_view src, std::span<char> dst) -> void
{
    std::ranges::fill(dst, '\0');
    const auto cut = cutUtf8(src, dst.size() - 1);
    std::ranges::copy(cut, dst.begin());
}

auto randomCaptureId() -> CaptureId
{
    std::random_device rd;
    CaptureId          id{};
    while (id == CaptureId{})
    {
        for (size_t i = 0; i < id.size(); i += 4)
        {
            const uint32_t word = rd();
            std::memcpy(id.data() + i, &word, 4);
        }
    }
    return id;
}

auto validateRule(const ExclusionRule& rule) -> void
{
    const bool isGame = rule.channel == static_cast<uint8_t>(Channel::Game);
    if (rule.action == ExclusionAction::Stub && !isGame)
    {
        throw Error(ErrorCode::InvalidPolicy,
                    std::format("xicap: channel {} does not define what a stub keeps", rule.channel));
    }
    if (rule.action == ExclusionAction::Stub && !rule.ranges.empty())
    {
        throw Error(ErrorCode::InvalidPolicy, "xicap: a stub rule has no byte ranges");
    }
    if (rule.ranges.size() > UINT16_MAX)
    {
        throw Error(ErrorCode::InvalidPolicy, "xicap: too many byte ranges in a rule");
    }
    if (rule.action != ExclusionAction::Stub && rule.action != ExclusionAction::ZeroRange)
    {
        throw Error(ErrorCode::InvalidPolicy, "xicap: unknown exclusion action");
    }
    // The header holds the opcode the entry repeats and the size a reader checks it against.
    if (isGame && std::ranges::any_of(rule.ranges, [](const ByteRange& range)
                                      {
                                          return range.offset < GAME_STUB_BYTES;
                                      }))
    {
        throw Error(ErrorCode::InvalidPolicy, std::format("xicap: a range for game opcode {:#05x} starts inside the 4-byte header", rule.opcode));
    }
}

auto validatePolicy(const ExclusionPolicy& policy) -> void
{
    if (policy.name.size() >= 32)
    {
        throw Error(ErrorCode::InvalidPolicy, "xicap: policy name over 31 bytes");
    }
    if (policy.rules.size() > UINT16_MAX)
    {
        throw Error(ErrorCode::InvalidPolicy, "xicap: too many policy rules");
    }
    std::ranges::for_each(policy.rules, validateRule);
}

auto encodePolicy(const ExclusionPolicy& policy) -> std::vector<uint8_t>
{
    std::vector<uint8_t>  out;
    ExclusionPolicyHeader header{
        .name      = {},
        .version   = policy.version,
        .ruleCount = static_cast<uint16_t>(policy.rules.size()),
        .reserved  = 0,
    };
    copyText(policy.name, header.name);
    appendPod(out, header);
    for (const auto& rule : policy.rules)
    {
        appendPod(out, ExclusionRuleHeader{
                           .channel    = rule.channel,
                           .direction  = static_cast<uint8_t>(rule.direction),
                           .action     = static_cast<uint8_t>(rule.action),
                           .reserved   = 0,
                           .opcode     = rule.opcode,
                           .rangeCount = static_cast<uint16_t>(rule.ranges.size()),
                       });
        for (const auto& range : rule.ranges)
        {
            appendPod(out, range);
        }
    }
    return out;
}

auto encodeSource(const SourceInfo& source) -> std::vector<uint8_t>
{
    if (source.metadata.size() > FrameLimits::MAX_EXTENSION_SIZE - sizeof(SourceHeader))
    {
        throw Error(ErrorCode::ExtensionTooLarge, "xicap: source metadata too large");
    }
    std::vector<uint8_t> out;
    SourceHeader         header{
        .format           = {},
        .formatVersion    = {},
        .skippedRecords   = source.skippedRecords,
        .utcOffsetSeconds = source.utcOffsetSeconds,
        .sourceHash       = source.sourceHash,
        .metadataLength   = static_cast<uint32_t>(source.metadata.size()),
    };
    copyText(source.format, header.format);
    copyText(source.formatVersion, header.formatVersion);
    appendPod(out, header);
    appendBytes(out, source.metadata);
    return out;
}

} // namespace

auto ruleFor(const ExclusionPolicy& policy, uint8_t channel, PacketDirection direction, uint16_t opcode) -> const ExclusionRule*
{
    const auto rule = std::ranges::find_if(policy.rules, [&](const ExclusionRule& r)
                                           {
                                               return r.channel == channel && r.opcode == opcode &&
                                                      (r.direction == ExclusionDirection::Both || static_cast<uint8_t>(r.direction) == static_cast<uint8_t>(direction));
                                           });
    if (rule == policy.rules.end())
    {
        return nullptr;
    }
    return &*rule;
}

auto applyPolicy(const ExclusionPolicy& policy, const OutPacket& packet) -> StoredPacket
{
    const bool isGame = packet.channel == static_cast<uint8_t>(Channel::Game);
    if (isGame && packet.data.size() < sizeof(FFXIPacketHeader))
    {
        throw Error(ErrorCode::PacketTooShort, "xicap: a game packet is at least 4 bytes");
    }

    StoredPacket stored{
        .opcode = packet.opcode,
        .flags  = static_cast<uint16_t>(packet.provenance & PacketFlag::Provenance),
        .data   = { packet.data.begin(), packet.data.end() },
    };
    if (isGame)
    {
        uint16_t firstWord = 0;
        std::memcpy(&firstWord, packet.data.data(), sizeof(firstWord));
        stored.opcode = firstWord & 0x1FFU;
    }
    if (packet.direction == PacketDirection::ClientToServer)
    {
        stored.flags |= PacketFlag::ClientToServer;
    }

    const auto* rule = ruleFor(policy, packet.channel, packet.direction, stored.opcode);
    if (rule == nullptr)
    {
        return stored;
    }
    validateRule(*rule);
    if (rule->action == ExclusionAction::Stub)
    {
        stored.data.resize(GAME_STUB_BYTES);
        stored.flags |= PacketFlag::Excluded;
        return stored;
    }
    for (const auto& range : rule->ranges)
    {
        if (range.offset < stored.data.size())
        {
            const auto length = std::min<uint64_t>(range.length, stored.data.size() - range.offset);
            std::fill_n(stored.data.begin() + range.offset, length, std::byte{ 0 });
        }
    }
    stored.flags |= PacketFlag::Redacted;
    return stored;
}

auto defaultExclusionPolicy() -> const ExclusionPolicy&
{
    // Packets carrying text players write to each other, from LandSandBoat's
    // definitions after atom0s's XiPackets: chat in every channel (0x017 in,
    // 0x0B5 out), tells (0x0B6 out), and the linkshell message board (0x0CC in,
    // 0x0E2 out).
    static const ExclusionPolicy policy{
        .name    = "xicap-default",
        .version = 1,
        .rules   = {
            { .channel = 0, .direction = ExclusionDirection::ServerToClient, .action = ExclusionAction::Stub, .opcode = 0x017, .ranges = {} },
            { .channel = 0, .direction = ExclusionDirection::ClientToServer, .action = ExclusionAction::Stub, .opcode = 0x0B5, .ranges = {} },
            { .channel = 0, .direction = ExclusionDirection::ClientToServer, .action = ExclusionAction::Stub, .opcode = 0x0B6, .ranges = {} },
            { .channel = 0, .direction = ExclusionDirection::ServerToClient, .action = ExclusionAction::Stub, .opcode = 0x0CC, .ranges = {} },
            { .channel = 0, .direction = ExclusionDirection::ClientToServer, .action = ExclusionAction::Stub, .opcode = 0x0E2, .ranges = {} },
        },
    };
    return policy;
}

Writer::Writer(const std::filesystem::path& path, WriterConfig config, FramePolicy policy)
: config_(std::move(config))
, policy_(policy)
, chain_(std::make_unique<internal::Chain>())
, key_(std::make_unique<internal::SigningKey>(config_.signingSeed))
, cctx_(ZSTD_createCCtx(), [](ZSTD_CCtx* c) noexcept
        {
            ZSTD_freeCCtx(c);
        })
{
    if (!cctx_)
    {
        throw Error(ErrorCode::ZstdContextFailed, "xicap: ZSTD_createCCtx failed");
    }
    validatePolicy(config_.policy);
    if ((config_.origin == Origin::Converted) != config_.source.has_value())
    {
        throw Error(ErrorCode::InvalidExtension, "xicap: a source block goes with converted captures, and only them");
    }
    policy_.maxPacketsPerFrame = std::min(policy_.maxPacketsPerFrame, FrameLimits::MAX_PACKETS);
    policy_.maxFrameSize       = std::min<size_t>(policy_.maxFrameSize, FrameLimits::MAX_CONTENT_SIZE);

    captureId_ = config_.captureId;
    if (captureId_ == CaptureId{})
    {
        captureId_ = randomCaptureId();
    }

    file_.open(path, std::ios::binary | std::ios::trunc);
    if (!file_)
    {
        throw Error(ErrorCode::OpenFailed, "xicap: cannot open " + path.string() + " for writing");
    }

    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_compressionLevel, policy_.compressionLevel);
    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_checksumFlag, 1);
    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_contentSizeFlag, 1);

    if (!policy_.dictionary.empty())
    {
        dictionary_.assign(policy_.dictionary.begin(), policy_.dictionary.end());
        dictionaryId_ = ZSTD_getDictID_fromDict(dictionary_.data(), dictionary_.size());
        if (dictionaryId_ == 0)
        {
            throw Error(ErrorCode::DictionaryMismatch, "xicap: the dictionary is not in zstd's dictionary format");
        }
        const size_t rc = ZSTD_CCtx_loadDictionary(cctx_.get(), dictionary_.data(), dictionary_.size());
        if (ZSTD_isError(rc))
        {
            throw Error(ErrorCode::ZstdContextFailed,
                        std::string("xicap: zstd load dictionary: ") + ZSTD_getErrorName(rc));
        }
    }

    frameBuffer_.reserve(policy_.maxFrameSize);
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
        // A destructor must not throw; the file reads as cut off.
    }
}

auto Writer::publicKey() const noexcept -> const PublicKey&
{
    return key_->publicKey();
}

auto Writer::addExtension(uint32_t type, std::span<const std::byte> data) -> void
{
    if (started_ || totalPackets_ > 0)
    {
        throw Error(ErrorCode::AddExtensionAfterPackets, "xicap: cannot add extensions after writing packets");
    }
    if (type < 0x8000 || type == 0xFFFFFFFF)
    {
        throw Error(ErrorCode::InvalidExtension,
                    std::format("xicap: extension type {:#x} is not in the range for other programs", type));
    }
    if (data.size() > FrameLimits::MAX_EXTENSION_SIZE)
    {
        throw Error(ErrorCode::ExtensionTooLarge, "xicap: extension block over 16 MiB");
    }
    const auto* p = reinterpret_cast<const uint8_t*>(data.data());
    extensions_.push_back({ type, std::vector<uint8_t>(p, p + data.size()) });
}

auto Writer::mark(MarkerKind kind, std::string_view text) -> void
{
    if (closed_)
    {
        throw Error(ErrorCode::WriterClosed, "xicap: writer is closed");
    }
    if (kind == MarkerKind::Login || kind == MarkerKind::Logout)
    {
        endFrame();
        if (unsignedFrames_ > 0)
        {
            checkpoint();
        }
    }
    if (pendingMarkers_.size() >= UINT16_MAX)
    {
        throw Error(ErrorCode::AddMarkerWithoutPacket, "xicap: too many markers before the next packet");
    }
    const auto cut = cutUtf8(text, MARKER_TEXT_MAX);
    pendingMarkers_.push_back({ kind, std::string(cut) });
    pendingMarkerBytes_ += sizeof(FrameMarker) + cut.size();
}

auto Writer::write(const OutPacket& packet) -> void
{
    if (closed_)
    {
        throw Error(ErrorCode::WriterClosed, "xicap: writer is closed");
    }
    if (packet.data.size() > FrameLimits::MAX_CONTENT_SIZE - sizeof(PacketEntry))
    {
        throw Error(ErrorCode::PacketTooLarge, std::format("xicap: packet of {} bytes is over the frame limit", packet.data.size()));
    }

    const auto stored = applyPolicy(config_.policy, packet);
    const auto data   = std::span{ reinterpret_cast<const uint8_t*>(stored.data.data()), stored.data.size() };

    // Timestamps never go backwards.
    const uint64_t timestamp = (totalPackets_ > 0) ? std::max(packet.timestamp, lastTimestamp_) : packet.timestamp;

    // Even alone in a frame, the packet must fit with the markers placed before it.
    if (sizeof(PacketEntry) + data.size() + pendingMarkerBytes_ > FrameLimits::MAX_CONTENT_SIZE)
    {
        throw Error(ErrorCode::PacketTooLarge, "xicap: packet and the markers before it are over the frame limit");
    }

    const bool zoneIn = packet.channel == static_cast<uint8_t>(Channel::Game) && packet.direction == PacketDirection::ServerToClient &&
                        stored.opcode == FFXIPacket::LOGIN_ZONE;
    if (zoneIn || shouldEndFrame(timestamp, sizeof(PacketEntry) + data.size()))
    {
        endFrame();
    }
    if (zoneIn && packet.data.size() >= FFXIPacket::LOGIN_ZONE_NO_OFFSET + 4)
    {
        uint32_t zone = 0;
        std::memcpy(&zone, packet.data.data() + FFXIPacket::LOGIN_ZONE_NO_OFFSET, sizeof(zone));
        currentZoneId_ = static_cast<uint16_t>(zone);
    }

    if (framePacketCount_ == 0)
    {
        frameBaseTimestamp_ = timestamp;
    }
    if (totalPackets_ == 0)
    {
        firstTimestamp_ = timestamp;
    }
    const auto deltaMs = static_cast<uint16_t>(framePacketCount_ == 0 ? 0 : timestamp - lastTimestamp_);
    lastTimestamp_     = timestamp;

    for (auto& marker : pendingMarkers_)
    {
        frameMarkers_.push_back({ static_cast<uint16_t>(framePacketCount_), std::move(marker) });
    }
    pendingMarkers_.clear();
    frameMarkerBytes_ += pendingMarkerBytes_;
    pendingMarkerBytes_ = 0;

    appendPod(frameBuffer_, PacketEntry{
                                .deltaMs  = deltaMs,
                                .flags    = stored.flags,
                                .channel  = packet.channel,
                                .reserved = 0,
                                .opcode   = stored.opcode,
                                .length   = static_cast<uint32_t>(data.size()),
                            });
    appendBytes(frameBuffer_, data);

    framePacketCount_++;
    totalPackets_++;
}

auto Writer::flush() -> void
{
    if (closed_)
    {
        return;
    }
    if (framePacketCount_ > 0)
    {
        endFrame();
    }
    else if (unsignedFrames_ > 0)
    {
        checkpoint();
    }
}

auto Writer::close() -> void
{
    if (closed_)
    {
        return;
    }
    endFrame();
    if (!started_)
    {
        writeStart();
    }
    writeFooter();
    file_.close();
    closed_ = true;
    if (!file_)
    {
        throw Error(ErrorCode::WriteFailed, "xicap: closing the capture failed");
    }
}

auto Writer::emit(std::span<const uint8_t> block) -> void
{
    file_.write(reinterpret_cast<const char*>(block.data()), static_cast<std::streamsize>(block.size()));
    file_.flush();
    if (!file_)
    {
        throw Error(ErrorCode::WriteFailed, std::format("xicap: write failed at offset {}", offset_));
    }
    offset_ += block.size();
}

auto Writer::writeStart() -> void
{
    Header header{};
    header.magic              = MAGIC;
    header.versionMajor       = VERSION_MAJOR;
    header.versionMinor       = VERSION_MINOR;
    header.headerSize         = HEADER_SIZE;
    header.extensionCount     = static_cast<uint32_t>(extensions_.size() + 1U + (dictionary_.empty() ? 0U : 1U) +
                                                      (config_.source ? 1U : 0U));
    header.captureId          = captureId_;
    header.previousCaptureId  = config_.previousCaptureId;
    header.startTimestamp     = totalPackets_ > 0 ? firstTimestamp_ : 0;
    header.clockSource        = config_.clockSource;
    header.origin             = config_.origin;
    header.network            = config_.network;
    header.startContext       = config_.startContext;
    header.dictionaryId       = dictionaryId_;
    header.signingKey         = key_->publicKey();
    header.character          = config_.character;
    header.character.reserved = 0;
    copyText(config_.captureAgent, header.captureAgent);
    copyText(config_.clientVersion, header.clientVersion);
    header.headerCrc = internal::crc32({ reinterpret_cast<const uint8_t*>(&header), offsetof(Header, headerCrc) });

    blockBuffer_.clear();
    appendPod(blockBuffer_, header);
    chain_->start(blockBuffer_);
    emit(blockBuffer_);

    const auto writeBlock = [this](uint32_t type, std::span<const uint8_t> payload)
    {
        blockBuffer_.clear();
        appendPod(blockBuffer_, ExtensionBlockHeader{ .type = type, .length = static_cast<uint32_t>(payload.size()) });
        appendBytes(blockBuffer_, payload);
        appendCrc(blockBuffer_);
        chain_->absorb(blockBuffer_);
        emit(blockBuffer_);
    };

    // The dictionary goes first so a reader can decode frames as they arrive.
    if (!dictionary_.empty())
    {
        writeBlock(EXT_ZSTD_DICT, dictionary_);
    }
    writeBlock(EXT_EXCLUSION_POLICY, encodePolicy(config_.policy));
    if (config_.source)
    {
        writeBlock(EXT_SOURCE, encodeSource(*config_.source));
    }
    for (const auto& ext : extensions_)
    {
        writeBlock(ext.type, ext.data);
    }
    started_ = true;
}

auto Writer::endFrame() -> void
{
    if (framePacketCount_ == 0)
    {
        return;
    }
    if (!started_)
    {
        writeStart();
    }

    for (const auto& [packetIndex, marker] : frameMarkers_)
    {
        appendPod(frameBuffer_, FrameMarker{
                                    .packetIndex = packetIndex,
                                    .kind        = marker.kind,
                                    .reserved    = 0,
                                    .textLength  = static_cast<uint16_t>(marker.text.size()),
                                });
        appendBytes(frameBuffer_, asBytes(marker.text));
    }

    compressedBuffer_.resize(ZSTD_compressBound(frameBuffer_.size()));
    const size_t compressedSize = ZSTD_compress2(cctx_.get(), compressedBuffer_.data(), compressedBuffer_.size(), frameBuffer_.data(), frameBuffer_.size());
    if (ZSTD_isError(compressedSize))
    {
        throw Error(ErrorCode::CompressFailed, std::string("xicap: zstd compress: ") + ZSTD_getErrorName(compressedSize));
    }
    totalUncompressedBytes_ += frameBuffer_.size();
    totalCompressedBytes_ += compressedSize;

    const uint64_t frameOffset = offset_;
    blockBuffer_.clear();
    appendPod(blockBuffer_, FrameHeader{
                                .magic         = FRAME_MAGIC,
                                .kind          = FrameKind::Packets,
                                .reserved0     = 0,
                                .markerCount   = static_cast<uint16_t>(frameMarkers_.size()),
                                .payloadSize   = static_cast<uint32_t>(compressedSize),
                                .packetCount   = framePacketCount_,
                                .baseTimestamp = frameBaseTimestamp_,
                                .zoneId        = currentZoneId_,
                                .reserved1     = 0,
                            });
    appendBytes(blockBuffer_, { compressedBuffer_.data(), compressedSize });
    appendCrc(blockBuffer_);
    chain_->absorb(blockBuffer_);
    emit(blockBuffer_);

    frameIndex_.push_back({
        .timestamp  = frameBaseTimestamp_,
        .fileOffset = frameOffset,
        .zoneId     = currentZoneId_,
        .reserved   = {},
    });

    if (unsignedFrames_ == 0)
    {
        firstUnsignedTimestamp_ = frameBaseTimestamp_;
    }
    unsignedFrames_++;
    totalFrames_++;
    frameBuffer_.clear();
    frameMarkers_.clear();
    frameMarkerBytes_ = 0;
    framePacketCount_ = 0;

    if (lastTimestamp_ - firstUnsignedTimestamp_ >= policy_.checkpointIntervalMs)
    {
        checkpoint();
    }
}

auto Writer::checkpoint() -> void
{
    const CheckpointPayload payload{
        .chain     = chain_->value(),
        .signature = key_->sign(internal::CHECKPOINT_PREFIX, chain_->value()),
    };
    blockBuffer_.clear();
    appendPod(blockBuffer_, FrameHeader{
                                .magic         = FRAME_MAGIC,
                                .kind          = FrameKind::Checkpoint,
                                .reserved0     = 0,
                                .markerCount   = 0,
                                .payloadSize   = sizeof(CheckpointPayload),
                                .packetCount   = 0,
                                .baseTimestamp = lastTimestamp_,
                                .zoneId        = currentZoneId_,
                                .reserved1     = 0,
                            });
    appendPod(blockBuffer_, payload);
    appendCrc(blockBuffer_);
    chain_->absorb(blockBuffer_);
    emit(blockBuffer_);
    unsignedFrames_ = 0;
    totalFrames_++;
}

auto Writer::writeFooter() -> void
{
    const uint64_t indexOffset = offset_;
    const auto     indexBytes  = std::span{ reinterpret_cast<const uint8_t*>(frameIndex_.data()),
                                            frameIndex_.size() * sizeof(FooterIndexEntry) };

    FooterTrailer trailer{
        .endTimestamp     = totalPackets_ > 0 ? lastTimestamp_ : 0,
        .totalPacketCount = totalPackets_,
        .reserved         = 0,
        .entryCount       = static_cast<uint32_t>(frameIndex_.size()),
        .indexOffset      = indexOffset,
        .indexCrc         = internal::crc32(indexBytes),
        .frameCount       = totalFrames_,
        .signature        = {},
        .trailerCrc       = 0,
        .magic            = FOOTER_MAGIC,
    };

    chain_->begin();
    chain_->update(indexBytes);
    chain_->update({ reinterpret_cast<const uint8_t*>(&trailer), offsetof(FooterTrailer, signature) });
    chain_->end();
    trailer.signature = key_->sign(internal::FOOTER_PREFIX, chain_->value());

    trailer.trailerCrc = internal::crc32({ reinterpret_cast<const uint8_t*>(&trailer), offsetof(FooterTrailer, trailerCrc) });

    blockBuffer_.assign(indexBytes.begin(), indexBytes.end());
    appendPod(blockBuffer_, trailer);
    emit(blockBuffer_);
}

auto Writer::shouldEndFrame(uint64_t timestamp, size_t added) const noexcept -> bool
{
    if (framePacketCount_ == 0)
    {
        return false;
    }
    // Markers are appended when the frame ends.
    return framePacketCount_ >= policy_.maxPacketsPerFrame ||
           frameBuffer_.size() >= policy_.maxFrameSize ||
           frameBuffer_.size() + added + frameMarkerBytes_ + pendingMarkerBytes_ > FrameLimits::MAX_CONTENT_SIZE ||
           frameMarkers_.size() + pendingMarkers_.size() > UINT16_MAX ||
           timestamp - frameBaseTimestamp_ >= policy_.maxFrameTimeMs ||
           timestamp - lastTimestamp_ > UINT16_MAX;
}

} // namespace xicap
