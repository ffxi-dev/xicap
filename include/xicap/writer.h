#pragma once

#include "constants.h"
#include "dictionary.h"
#include "types.h"

#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

struct ZSTD_CCtx_s;

namespace xicap
{

namespace internal
{
class Chain;
class SigningKey;
} // namespace internal

// Stubs chat on the game channel in both directions. See FORMAT.md, Exclusion.
[[nodiscard]] auto defaultExclusionPolicy() -> const ExclusionPolicy&;

// Per-capture metadata, written into the header and the format-level
// extension blocks.
struct WriterConfig
{
    std::string       clientVersion;
    std::string       captureAgent;
    CharacterIdentity character{};
    ClockSource       clockSource  = ClockSource::Live;
    Origin            origin       = Origin::Live;
    Network           network      = Network::Unknown;
    StartContext      startContext = StartContext::Login;
    CaptureId         captureId{}; // all zero: the writer picks a random id
    CaptureId         previousCaptureId{};
    SecretSeed        signingSeed{}; // the recorder install's Ed25519 seed
    ExclusionPolicy   policy = defaultExclusionPolicy();
    // Required when origin is Converted, refused otherwise.
    std::optional<SourceInfo> source;
};

// When the writer ends a frame. Defaults suit FFXI.
struct FramePolicy
{
    size_t   maxFrameSize         = FrameLimits::MAX_COMPRESSED_SIZE;
    uint32_t maxPacketsPerFrame   = FrameLimits::MAX_PACKET_COUNT;
    uint64_t maxFrameTimeMs       = FrameLimits::MAX_TIME_WINDOW_MS;
    uint64_t checkpointIntervalMs = CHECKPOINT_INTERVAL_MS;
    int      compressionLevel     = 12;

    // Dictionary used to compress frames; the capture carries a copy. Empty
    // disables dictionary use.
    std::span<const uint8_t> dictionary = builtinDictionary();
};

struct OutPacket
{
    uint64_t                   timestamp{};
    PacketDirection            direction{};
    std::span<const std::byte> data;
    uint8_t                    channel = static_cast<uint8_t>(Channel::Game);
    // Ignored on the game channel, where the opcode comes from the packet header.
    uint16_t opcode{};
    // PacketFlag::Injected, Blocked, Modified, FirstInChunk.
    uint16_t provenance{};
};

class Writer
{
public:
    Writer(const std::filesystem::path& path, WriterConfig config, FramePolicy policy = {});
    ~Writer();

    Writer(const Writer&)                    = delete;
    Writer(Writer&&)                         = delete;
    auto operator=(const Writer&) -> Writer& = delete;
    auto operator=(Writer&&) -> Writer&      = delete;

    // Metadata blocks in the range 0x8000 to 0xFFFFFFFE. Must be called before
    // the first packet.
    auto addExtension(uint32_t type, std::span<const std::byte> data) -> void;

    auto write(const OutPacket& packet) -> void;
    auto write(uint64_t timestamp, PacketDirection direction, std::span<const std::byte> data) -> void
    {
        write(OutPacket{ .timestamp = timestamp, .direction = direction, .data = data });
    }

    // Places a marker just before the next packet written. A login or logout
    // also ends the frame being built and signs what came before.
    auto mark(MarkerKind kind, std::string_view text = {}) -> void;

    // Ends the frame being built. When there was none, the capture is idle and
    // any frames since the last checkpoint are signed. Call it on a timer.
    auto flush() -> void;
    auto close() -> void;

    [[nodiscard]] auto captureId() const noexcept -> const CaptureId&
    {
        return captureId_;
    }
    [[nodiscard]] auto publicKey() const noexcept -> const PublicKey&;

    [[nodiscard]] auto packetsWritten() const noexcept -> uint64_t
    {
        return totalPackets_;
    }
    [[nodiscard]] auto framesWritten() const noexcept -> uint32_t
    {
        return totalFrames_;
    }
    [[nodiscard]] auto uncompressedBytes() const noexcept -> uint64_t
    {
        return totalUncompressedBytes_;
    }
    [[nodiscard]] auto compressedBytes() const noexcept -> uint64_t
    {
        return totalCompressedBytes_;
    }
    [[nodiscard]] auto bytesWritten() const noexcept -> uint64_t
    {
        return offset_;
    }

private:
    struct PendingMarker
    {
        MarkerKind  kind;
        std::string text;
    };
    struct FrameMarkerEntry
    {
        uint16_t      packetIndex;
        PendingMarker marker;
    };

    auto               emit(std::span<const uint8_t> block) -> void;
    auto               writeStart() -> void;
    auto               writeFooter() -> void;
    auto               endFrame() -> void;
    auto               checkpoint() -> void;
    [[nodiscard]] auto shouldEndFrame(uint64_t timestamp, size_t added) const noexcept -> bool;

    std::ofstream file_;
    WriterConfig  config_;
    FramePolicy   policy_;
    CaptureId     captureId_{};
    bool          started_{ false };
    bool          closed_{ false };
    uint64_t      offset_{ 0 };

    std::vector<ExtensionBlock> extensions_;
    std::vector<uint8_t>        dictionary_;
    uint32_t                    dictionaryId_{ 0 };

    std::vector<uint8_t>          frameBuffer_;
    std::vector<uint8_t>          compressedBuffer_;
    std::vector<uint8_t>          blockBuffer_;
    uint64_t                      frameBaseTimestamp_{ 0 };
    uint64_t                      lastTimestamp_{ 0 };
    uint64_t                      firstTimestamp_{ 0 };
    uint32_t                      framePacketCount_{ 0 };
    uint16_t                      currentZoneId_{ 0 };
    std::vector<PendingMarker>    pendingMarkers_;
    std::vector<FrameMarkerEntry> frameMarkers_;
    std::vector<FooterIndexEntry> frameIndex_;

    // Frames written since the last checkpoint, and the first one's time.
    uint32_t unsignedFrames_{ 0 };
    uint64_t firstUnsignedTimestamp_{ 0 };

    uint64_t totalPackets_{ 0 };
    uint32_t totalFrames_{ 0 };
    uint64_t totalUncompressedBytes_{ 0 };
    uint64_t totalCompressedBytes_{ 0 };

    std::unique_ptr<internal::Chain>                     chain_;
    std::unique_ptr<internal::SigningKey>                key_;
    std::unique_ptr<ZSTD_CCtx_s, void (*)(ZSTD_CCtx_s*)> cctx_;
};

} // namespace xicap
