#include "xicap/writer.h"
#include "internal/access.h"
#include "internal/chain.h"
#include "internal/columns.h"
#include "internal/crc32.h"
#include "internal/varint.h"

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
// What a marker adds to the plaintext, at most: packetIndex, kind, and textLength.
inline constexpr size_t MARKER_COST = 5 + 1 + 3;
constexpr uint8_t       GAME        = static_cast<uint8_t>(Channel::Game);
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

// The length of the valid UTF-8 character text starts with, or 0.
auto utf8Length(std::string_view text) -> size_t
{
    const auto at = [&](size_t i) -> unsigned
    {
        return i < text.size() ? static_cast<uint8_t>(text[i]) : 0x100U;
    };
    const auto tail = [&](size_t n) -> bool
    {
        for (size_t i = 1; i <= n; ++i)
        {
            if ((at(i) & 0xC0U) != 0x80U)
            {
                return false;
            }
        }
        return true;
    };
    const unsigned b0 = at(0);
    const unsigned b1 = at(1);
    if (b0 < 0x80)
    {
        return 1;
    }
    if (b0 >= 0xC2 && b0 <= 0xDF)
    {
        return tail(1) ? 2 : 0;
    }
    if (b0 >= 0xE0 && b0 <= 0xEF)
    {
        const bool ok = (b0 == 0xE0 ? b1 >= 0xA0 : b0 == 0xED ? b1 < 0xA0
                                                              : true) &&
                        tail(2);
        return ok ? 3 : 0;
    }
    if (b0 >= 0xF0 && b0 <= 0xF4)
    {
        const bool ok = (b0 == 0xF0 ? b1 >= 0x90 : b0 == 0xF4 ? b1 < 0x90
                                                              : true) &&
                        tail(3);
        return ok ? 4 : 0;
    }
    return 0;
}

// FORMAT.md's text is UTF-8, but hosts pass what they have: Ashita hands over Shift-JIS. Each byte that does not
// start a valid character becomes U+FFFD.
auto toUtf8(std::string_view text) -> std::string
{
    std::string out;
    out.reserve(text.size());
    while (!text.empty())
    {
        const auto n = utf8Length(text);
        out.append(n == 0 ? std::string_view{ "\xEF\xBF\xBD" } : text.substr(0, n));
        text.remove_prefix(n == 0 ? 1 : n);
    }
    return out;
}

auto copyText(std::string_view src, std::span<char> dst) -> void
{
    std::ranges::fill(dst, '\0');
    const auto text = toUtf8(src);
    std::ranges::copy(cutUtf8(text, dst.size() - 1), dst.begin());
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
    // The block must fit the 16 MiB a reader takes.
    uint64_t size = sizeof(ExclusionPolicyHeader);
    for (const auto& rule : policy.rules)
    {
        size += sizeof(ExclusionRuleHeader) + rule.ranges.size() * sizeof(ByteRange);
    }
    if (size > FrameLimits::MAX_EXTENSION_SIZE)
    {
        throw Error(ErrorCode::InvalidPolicy, "xicap: the exclusion policy is over 16 MiB");
    }
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

auto encodeSourceSigner(const SourceSigner& signer) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    appendPod(out, SourceSignerBlock{ .signingKey = signer.key, .verifiedPackets = signer.verifiedPackets, .flags = signer.signedToEnd ? SourceSignerFlag::SignedToEnd : uint8_t{ 0 }, .reserved = {} });
    return out;
}

} // namespace

namespace internal
{

auto encodeBlock(uint32_t type, std::span<const uint8_t> payload) -> std::vector<uint8_t>
{
    std::vector<uint8_t> block;
    appendPod(block, ExtensionBlockHeader{ .type = type, .length = static_cast<uint32_t>(payload.size()) });
    appendBytes(block, payload);
    appendCrc(block);
    return block;
}

auto encodeSource(const SourceInfo& source) -> std::vector<uint8_t>
{
    return xicap::encodeSource(source);
}

auto encodeSourceSigner(const SourceSigner& signer) -> std::vector<uint8_t>
{
    return xicap::encodeSourceSigner(signer);
}

} // namespace internal

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
    // 0x0B5 out), tells (0x0B6 out), the Assist Channel (0x0B7 out), and the
    // linkshell message board (0x0CC in, 0x0E2 out).
    static const ExclusionPolicy policy{
        .name    = "xicap-default",
        .version = 2,
        .rules   = {
            { .channel = 0, .direction = ExclusionDirection::ServerToClient, .action = ExclusionAction::Stub, .opcode = 0x017, .ranges = {} },
            { .channel = 0, .direction = ExclusionDirection::ClientToServer, .action = ExclusionAction::Stub, .opcode = 0x0B5, .ranges = {} },
            { .channel = 0, .direction = ExclusionDirection::ClientToServer, .action = ExclusionAction::Stub, .opcode = 0x0B6, .ranges = {} },
            { .channel = 0, .direction = ExclusionDirection::ClientToServer, .action = ExclusionAction::Stub, .opcode = 0x0B7, .ranges = {} },
            { .channel = 0, .direction = ExclusionDirection::ServerToClient, .action = ExclusionAction::Stub, .opcode = 0x0CC, .ranges = {} },
            { .channel = 0, .direction = ExclusionDirection::ClientToServer, .action = ExclusionAction::Stub, .opcode = 0x0E2, .ranges = {} },
        },
    };
    return policy;
}

Writer::Writer(const std::filesystem::path& path, WriterConfig config, FramePolicy policy)
: config_(std::move(config))
, policy_(policy)
, stream_(std::make_unique<internal::SignedStream>())
, key_(std::make_unique<internal::SigningKey>(config_.signingSeed))
, cctx_(ZSTD_createCCtx(), [](ZSTD_CCtx* c) noexcept
        {
            ZSTD_freeCCtx(c);
        })
{
    validatePolicy(config_.policy);
    if (config_.recordingMode == RecordingMode::Everything && !config_.policy.rules.empty())
    {
        throw Error(ErrorCode::InvalidPolicy, "xicap: a recording that keeps everything has a policy with no rules");
    }
    if (static_cast<uint8_t>(config_.recordingMode) > static_cast<uint8_t>(RecordingMode::Anonymous))
    {
        throw Error(ErrorCode::UnknownRecordingMode, "xicap: unknown recording mode");
    }
    if ((config_.origin == Origin::Converted) != config_.source.has_value())
    {
        throw Error(ErrorCode::InvalidExtension, "xicap: a source block goes with converted captures, and only them");
    }
    captureId_ = config_.captureId;
    if (captureId_ == CaptureId{})
    {
        captureId_ = randomCaptureId();
    }
    open(path);
}

Writer::Writer(const std::filesystem::path& path, FramePolicy policy, std::vector<uint8_t> header, std::vector<std::vector<uint8_t>> blocks, const SecretSeed* signer)
: policy_(policy)
, headerBytes_(std::move(header))
, blockBytes_(std::move(blocks))
, stream_(std::make_unique<internal::SignedStream>())
, key_(signer ? std::make_unique<internal::SigningKey>(*signer) : nullptr)
, cctx_(ZSTD_createCCtx(), [](ZSTD_CCtx* c) noexcept
        {
            ZSTD_freeCCtx(c);
        })
{
    std::memcpy(captureId_.data(), headerBytes_.data() + offsetof(Header, captureId), captureId_.size());
    open(path);
}

auto Writer::open(const std::filesystem::path& path) -> void
{
    if (!cctx_)
    {
        throw Error(ErrorCode::ZstdContextFailed, "xicap: ZSTD_createCCtx failed");
    }
    policy_.maxPacketsPerFrame = std::clamp<uint32_t>(policy_.maxPacketsPerFrame, 1, FrameLimits::MAX_PACKETS);
    policy_.maxFrameSize       = std::min<size_t>(policy_.maxFrameSize, FrameLimits::MAX_CONTENT_SIZE);
    policy_.restartBytes       = std::min<size_t>(policy_.restartBytes, FrameLimits::MAX_CONTENT_SIZE);
    policy_.windowLog          = std::clamp(policy_.windowLog, 10, FrameLimits::MAX_WINDOW_LOG);

    file_.open(path, std::ios::binary | std::ios::trunc);
    if (!file_)
    {
        throw Error(ErrorCode::OpenFailed, "xicap: cannot open " + path.string() + " for writing");
    }
    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_compressionLevel, policy_.compressionLevel);
    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_windowLog, policy_.windowLog);
    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_hashLog, policy_.hashLog);
    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_checksumFlag, 1);
    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_contentSizeFlag, 0);
    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_dictIDFlag, 0);
}

Writer::~Writer()
{
    if (closed_ || failed_ || !file_.is_open())
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

auto Writer::usable() const -> void
{
    if (closed_)
    {
        throw Error(ErrorCode::WriterClosed, "xicap: writer is closed");
    }
    if (failed_)
    {
        throw Error(ErrorCode::WriteFailed, "xicap: an earlier write failed; the file ends cut off before it");
    }
}

auto Writer::mark(MarkerKind kind, std::string_view text) -> void
{
    usable();
    if ((kind == MarkerKind::Login || kind == MarkerKind::Logout) && checkpoints())
    {
        endFrame(false);
        if (unsignedFrames_ > 0)
        {
            checkpoint();
        }
    }
    const auto utf8 = toUtf8(text);
    queueMarker(kind, cutUtf8(utf8, MARKER_TEXT_MAX));
}

// As given: a copy keeps a marker whole, up to the format's 65,535 bytes.
auto Writer::queueMarker(MarkerKind kind, std::string_view text) -> void
{
    if (pendingMarkers_.size() >= UINT16_MAX)
    {
        throw Error(ErrorCode::AddMarkerWithoutPacket, "xicap: too many markers before the next packet");
    }
    if (text.size() > UINT16_MAX)
    {
        throw Error(ErrorCode::PacketTooLarge, "xicap: marker text over 65,535 bytes");
    }
    pendingMarkers_.push_back({ kind, std::string(text) });
    pendingMarkerBytes_ += MARKER_COST + text.size();
}

auto Writer::write(const OutPacket& packet) -> void
{
    usable();
    if (packet.data.size() > FrameLimits::MAX_CONTENT_SIZE)
    {
        throw Error(ErrorCode::PacketTooLarge, std::format("xicap: packet of {} bytes is over the frame limit", packet.data.size()));
    }
    const auto stored = applyPolicy(config_.policy, packet);
    add(packet.timestamp, stored.flags, packet.channel, stored.opcode, { reinterpret_cast<const uint8_t*>(stored.data.data()), stored.data.size() });
}

auto Writer::packetCost(uint64_t timestamp, uint16_t flags, uint8_t channel, uint16_t opcode, size_t length) const -> size_t
{
    using internal::varintSize;
    const uint64_t delta = framePackets_.empty() ? 0 : timestamp - lastTimestamp_;
    size_t         cost  = varintSize(delta) + varintSize(flags) + varintSize(channel) + varintSize(opcode) + varintSize(uint64_t{ length } + 1) + length;
    if (channel == GAME)
    {
        cost += 3; // sync
    }
    const auto key = (uint32_t{ channel } << 17) | (static_cast<uint32_t>(flags & PacketFlag::ClientToServer) << 16) | opcode;
    if (!frameGroups_.contains(key))
    {
        cost += 5; // group size
    }
    return cost;
}

auto Writer::add(uint64_t timestamp, uint16_t flags, uint8_t channel, uint16_t opcode, std::span<const uint8_t> data) -> void
{
    // Timestamps never go backwards.
    timestamp = totalPackets_ > 0 ? std::max(timestamp, lastTimestamp_) : timestamp;

    size_t added = packetCost(timestamp, flags, channel, opcode, data.size());
    // Even alone in a frame, the packet must fit with the markers placed before it.
    if (added + pendingMarkerBytes_ > FrameLimits::MAX_CONTENT_SIZE)
    {
        throw Error(ErrorCode::PacketTooLarge, "xicap: packet and the markers before it are over the frame limit");
    }
    const bool zoneIn = channel == GAME && (flags & PacketFlag::ClientToServer) == 0 && opcode == FFXIPacket::LOGIN_ZONE;
    if (zoneIn || shouldEndFrame(timestamp, added))
    {
        endFrame(false);
        added = packetCost(timestamp, flags, channel, opcode, data.size());
    }
    if (zoneIn && data.size() >= FFXIPacket::LOGIN_ZONE_NO_OFFSET + 4)
    {
        uint32_t zone = 0;
        std::memcpy(&zone, data.data() + FFXIPacket::LOGIN_ZONE_NO_OFFSET, sizeof(zone));
        currentZoneId_ = static_cast<uint16_t>(zone);
    }
    if (framePackets_.empty())
    {
        frameBaseTimestamp_ = timestamp;
    }
    if (totalPackets_ == 0)
    {
        firstTimestamp_ = timestamp;
    }
    for (auto& marker : pendingMarkers_)
    {
        frameMarkers_.push_back({ static_cast<uint32_t>(framePackets_.size()), std::move(marker) });
    }
    pendingMarkers_.clear();
    frameSize_ += added + pendingMarkerBytes_;
    pendingMarkerBytes_ = 0;

    frameGroups_.insert((uint32_t{ channel } << 17) | (static_cast<uint32_t>(flags & PacketFlag::ClientToServer) << 16) | opcode);
    framePackets_.push_back({ .timestamp = timestamp, .flags = flags, .channel = channel, .opcode = opcode, .offset = frameBytes_.size(), .length = data.size() });
    frameBytes_.insert(frameBytes_.end(), data.begin(), data.end());
    lastTimestamp_ = timestamp;
    totalPackets_++;
}

auto Writer::flush() -> void
{
    if (closed_)
    {
        return;
    }
    usable();
    if (!framePackets_.empty())
    {
        endFrame(false);
    }
    else if (unsignedFrames_ > 0 && checkpoints())
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
    usable();
    endFrame(true);
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
        failed_ = true;
        throw Error(ErrorCode::WriteFailed, std::format("xicap: write failed at offset {}", offset_));
    }
    offset_ += block.size();
}

auto Writer::writeStart() -> void
{
    if (headerBytes_.empty())
    {
        Header header{};
        header.magic              = MAGIC;
        header.versionMajor       = VERSION_MAJOR;
        header.versionMinor       = VERSION_MINOR;
        header.headerSize         = HEADER_SIZE;
        header.extensionCount     = static_cast<uint32_t>(extensions_.size() + 1U + (config_.source ? 1U : 0U) + (config_.source && config_.source->signer ? 1U : 0U));
        header.captureId          = captureId_;
        header.previousCaptureId  = config_.previousCaptureId;
        header.startTimestamp     = totalPackets_ > 0 ? firstTimestamp_ : 0;
        header.clockSource        = config_.clockSource;
        header.origin             = config_.origin;
        header.network            = config_.network;
        header.startContext       = config_.startContext;
        header.recordingMode      = config_.recordingMode;
        header.dictionaryId       = 0;
        header.signingKey         = key_->publicKey();
        header.character          = config_.character;
        header.character.reserved = 0;
        copyText(config_.captureAgent, header.captureAgent);
        copyText(config_.clientVersion, header.clientVersion);
        header.headerCrc = internal::crc32({ reinterpret_cast<const uint8_t*>(&header), offsetof(Header, headerCrc) });
        appendPod(headerBytes_, header);

        const auto addBlock = [this](uint32_t type, std::span<const uint8_t> payload)
        {
            blockBytes_.push_back(internal::encodeBlock(type, payload));
        };
        addBlock(EXT_EXCLUSION_POLICY, encodePolicy(config_.policy));
        if (config_.source)
        {
            addBlock(EXT_SOURCE, encodeSource(*config_.source));
            if (config_.source->signer)
            {
                addBlock(EXT_SOURCE_SIGNER, encodeSourceSigner(*config_.source->signer));
            }
        }
        for (const auto& ext : extensions_)
        {
            addBlock(ext.type, ext.data);
        }
    }
    stream_->bytes(headerBytes_);
    emit(headerBytes_);
    for (const auto& block : blockBytes_)
    {
        stream_->bytes(block);
        emit(block);
    }
    started_ = true;
}

auto Writer::compress(std::span<const uint8_t> plain, bool endStream) -> size_t
{
    compressedBuffer_.resize(ZSTD_compressBound(plain.size()) + 1024);
    ZSTD_inBuffer  in{ plain.data(), plain.size(), 0 };
    ZSTD_outBuffer out{ compressedBuffer_.data(), compressedBuffer_.size(), 0 };
    while (true)
    {
        const size_t rc = ZSTD_compressStream2(cctx_.get(), &out, &in, endStream ? ZSTD_e_end : ZSTD_e_flush);
        if (ZSTD_isError(rc))
        {
            throw Error(ErrorCode::CompressFailed, std::string("xicap: zstd compress: ") + ZSTD_getErrorName(rc));
        }
        if (rc == 0)
        {
            return out.pos;
        }
        compressedBuffer_.resize(compressedBuffer_.size() * 2);
        out.dst  = compressedBuffer_.data();
        out.size = compressedBuffer_.size();
    }
}

// The signed stream takes a frame's packets before the frame is written, so once writing a frame fails the footer
// could sign packets the file does not hold: the writer stops, and the file reads as cut off.
auto Writer::endFrame(bool last) -> void
{
    try
    {
        writeFrame(last);
    }
    catch (...)
    {
        failed_ = true;
        throw;
    }
}

auto Writer::writeFrame(bool last) -> void
{
    if (framePackets_.empty())
    {
        return;
    }
    if (!started_)
    {
        writeStart();
    }

    std::vector<internal::Record> records;
    records.reserve(framePackets_.size());
    for (const auto& p : framePackets_)
    {
        records.push_back({ .timestamp = p.timestamp, .flags = p.flags, .channel = p.channel, .opcode = p.opcode, .data = { frameBytes_.data() + p.offset, p.length } });
    }
    std::vector<internal::MarkerRecord> markers;
    markers.reserve(frameMarkers_.size());
    for (const auto& m : frameMarkers_)
    {
        markers.push_back({ .packetIndex = m.packetIndex, .kind = m.marker.kind, .text = m.marker.text });
    }
    const auto plain = internal::encodeColumns(records, markers);

    size_t nextMarker = 0;
    for (uint32_t i = 0; i < records.size(); ++i)
    {
        for (; nextMarker < markers.size() && markers[nextMarker].packetIndex == i; ++nextMarker)
        {
            stream_->marker(markers[nextMarker].kind, markers[nextMarker].text);
        }
        stream_->packet(records[i]);
    }

    const bool restart = nextRestart_;
    if (restart)
    {
        ZSTD_CCtx_reset(cctx_.get(), ZSTD_reset_session_only);
        streamPlain_ = 0;
    }
    streamPlain_ += plain.size();
    const bool   endStream      = last || streamPlain_ + policy_.maxFrameSize > policy_.restartBytes;
    const size_t compressedSize = compress(plain, endStream);
    nextRestart_                = endStream;
    totalUncompressedBytes_ += plain.size();
    totalCompressedBytes_ += compressedSize;

    const uint64_t frameOffset = offset_;
    blockBuffer_.clear();
    appendPod(blockBuffer_, FrameHeader{
                                .magic         = FRAME_MAGIC,
                                .kind          = FrameKind::Packets,
                                .frameFlags    = restart ? FrameFlag::Restart : uint8_t{ 0 },
                                .markerCount   = static_cast<uint16_t>(frameMarkers_.size()),
                                .payloadSize   = static_cast<uint32_t>(compressedSize),
                                .packetCount   = static_cast<uint32_t>(framePackets_.size()),
                                .baseTimestamp = frameBaseTimestamp_,
                                .zoneId        = currentZoneId_,
                                .reserved      = 0,
                                .plainSize     = static_cast<uint32_t>(plain.size()),
                            });
    appendBytes(blockBuffer_, { compressedBuffer_.data(), compressedSize });
    appendCrc(blockBuffer_);
    emit(blockBuffer_);

    frameIndex_.push_back({
        .timestamp  = frameBaseTimestamp_,
        .fileOffset = frameOffset,
        .zoneId     = currentZoneId_,
        .flags      = restart ? IndexFlag::Restart : uint8_t{ 0 },
        .reserved   = {},
    });

    if (unsignedFrames_ == 0)
    {
        firstUnsignedTimestamp_ = frameBaseTimestamp_;
    }
    unsignedFrames_++;
    totalFrames_++;
    writtenPackets_ += framePackets_.size();
    frameBytes_.clear();
    framePackets_.clear();
    frameGroups_.clear();
    frameMarkers_.clear();
    frameSize_ = 0;

    if (checkpoints() && lastTimestamp_ - firstUnsignedTimestamp_ >= policy_.checkpointIntervalMs)
    {
        checkpoint();
    }
}

auto Writer::checkpoint() -> void
{
    const auto digest = stream_->digest();
    writeCheckpoint({ .packets = writtenPackets_, .digest = digest, .signature = key_->sign(internal::signedMessage(internal::CHECKPOINT_PREFIX, digest)) });
}

auto Writer::writeCheckpoint(const CheckpointPayload& payload) -> void
{
    blockBuffer_.clear();
    appendPod(blockBuffer_, FrameHeader{
                                .magic         = FRAME_MAGIC,
                                .kind          = FrameKind::Checkpoint,
                                .frameFlags    = 0,
                                .markerCount   = 0,
                                .payloadSize   = sizeof(CheckpointPayload),
                                .packetCount   = 0,
                                .baseTimestamp = lastTimestamp_,
                                .zoneId        = currentZoneId_,
                                .reserved      = 0,
                                .plainSize     = 0,
                            });
    appendPod(blockBuffer_, payload);
    appendCrc(blockBuffer_);
    emit(blockBuffer_);
    unsignedFrames_ = 0;
    totalFrames_++;
}

auto Writer::writeFooter() -> void
{
    const uint64_t endTimestamp = totalPackets_ > 0 ? lastTimestamp_ : 0;
    const auto     end          = stream_->end(totalPackets_, endTimestamp);
    const auto     indexBytes   = std::span{ reinterpret_cast<const uint8_t*>(frameIndex_.data()), frameIndex_.size() * sizeof(FooterIndexEntry) };

    FooterTrailer trailer{
        .endTimestamp     = endTimestamp,
        .totalPacketCount = totalPackets_,
        .trailerFlags     = (sealKey_ ? TrailerFlag::Sealed : 0U) | (footerSignature_ == FooterSignature::Unsigned ? TrailerFlag::EndUnsigned : 0U),
        .entryCount       = static_cast<uint32_t>(frameIndex_.size()),
        .indexOffset      = offset_,
        .indexCrc         = internal::crc32(indexBytes),
        .frameCount       = totalFrames_,
        .signature        = {},
        .trailerCrc       = 0,
        .magic            = FOOTER_MAGIC,
    };
    switch (footerSignature_)
    {
        case FooterSignature::Sign:
            trailer.signature = key_->sign(internal::signedMessage(internal::FOOTER_PREFIX, end));
            break;
        case FooterSignature::Copy:
            trailer.signature = copiedSignature_;
            break;
        case FooterSignature::Unsigned:
            break;
    }
    trailer.trailerCrc = internal::crc32({ reinterpret_cast<const uint8_t*>(&trailer), offsetof(FooterTrailer, trailerCrc) });

    blockBuffer_.assign(indexBytes.begin(), indexBytes.end());
    if (sealKey_)
    {
        SealBlock seal{ .magic = SEAL_MAGIC, .reserved0 = 0, .sealedAt = sealedAt_, .key = sealKey_->publicKey(), .agent = {}, .signature = {}, .reserved1 = {}, .crc = 0 };
        copyText(sealAgent_, seal.agent);
        const auto* bytes = reinterpret_cast<const uint8_t*>(&seal);
        const auto* kept  = reinterpret_cast<const uint8_t*>(&keptCheckpoint_);
        // The seal covers the signer's evidence too: its footer signature and the checkpoint it keeps.
        seal.signature = sealKey_->sign(internal::signedMessage(internal::SEAL_PREFIX, end, trailer.signature, std::span{ kept, sizeof(CheckpointPayload) }, std::span{ bytes, offsetof(SealBlock, signature) }));
        seal.crc       = internal::crc32({ bytes, offsetof(SealBlock, crc) });
        appendPod(blockBuffer_, seal);
    }
    appendPod(blockBuffer_, trailer);
    emit(blockBuffer_);
}

auto Writer::shouldEndFrame(uint64_t timestamp, size_t added) const noexcept -> bool
{
    if (framePackets_.empty())
    {
        return false;
    }
    return framePackets_.size() >= policy_.maxPacketsPerFrame ||
           frameSize_ + added + pendingMarkerBytes_ > policy_.maxFrameSize ||
           frameMarkers_.size() + pendingMarkers_.size() > UINT16_MAX ||
           timestamp - frameBaseTimestamp_ >= policy_.maxFrameTimeMs ||
           timestamp - lastTimestamp_ > UINT32_MAX;
}

} // namespace xicap
