#pragma once

#include "constants.h"
#include "types.h"

#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

struct ZSTD_CCtx_s;

namespace xicap
{

namespace internal
{
class SignedStream;
class SigningKey;
struct Access;
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

// How the writer frames and compresses packets. See FORMAT.md, Writer rules.
struct FramePolicy
{
    size_t   maxFrameSize       = 64 * 1024; // plaintext bytes, at most 16 MiB
    uint32_t maxPacketsPerFrame = 1000;      // at most 1,048,576
    uint64_t maxFrameTimeMs     = 5000;
    // 0 writes no checkpoint at all.
    uint64_t checkpointIntervalMs = CHECKPOINT_INTERVAL_MS;
    int      compressionLevel     = 7;
    // The writer ends a stream after a frame when its plaintext since the restart, plus maxFrameSize, would pass
    // this. At most 16 MiB.
    size_t restartBytes = 4 * 1024 * 1024;
    // The zstd window, as a power of two; at most 23.
    int windowLog = 21;
    // zstd's match table, as a power of two; 0 for the level's own. It sets most of the compressor's memory.
    int hashLog = 19;

    // What a recorder writes: level 7, a 2 MiB window, and a 2^19 match table, about 5.5 MB of compressor. The
    // default.
    static auto live() -> FramePolicy
    {
        return {};
    }

    // What an archive writes: level 19, frames to each zone-in or 1 MiB in streams of up to 4 MiB, no
    // checkpoints. About 81 MB of compressor.
    static auto archive() -> FramePolicy
    {
        return {
            .maxFrameSize         = 1024 * 1024,
            .maxPacketsPerFrame   = FrameLimits::MAX_PACKETS,
            .maxFrameTimeMs       = UINT64_MAX,
            .checkpointIntervalMs = 0,
            .compressionLevel     = 19,
            .restartBytes         = 4 * 1024 * 1024,
            .windowLog            = 22,
            .hashLog              = 0,
        };
    }
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

// A packet as the writer stores it.
struct StoredPacket
{
    uint16_t               opcode{};
    uint16_t               flags{};
    std::vector<std::byte> data;
};

// The rule the writer applies to such a packet: the first that matches, or none.
[[nodiscard]] auto ruleFor(const ExclusionPolicy& policy, uint8_t channel, PacketDirection direction, uint16_t opcode) -> const ExclusionRule*;

// Applies the first rule that matches and sets the flags, as Writer::write does. Throws PacketTooShort for a game packet under 4 bytes, and InvalidPolicy for a rule a Writer would refuse.
[[nodiscard]] auto applyPolicy(const ExclusionPolicy& policy, const OutPacket& packet) -> StoredPacket;

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
    // also ends the frame being built and signs what came before, when the
    // policy writes checkpoints.
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
    friend struct internal::Access;

    struct PendingMarker
    {
        MarkerKind  kind;
        std::string text;
    };
    struct FrameMarkerEntry
    {
        uint32_t      packetIndex;
        PendingMarker marker;
    };
    struct FramePacket
    {
        uint64_t timestamp;
        uint16_t flags;
        uint8_t  channel;
        uint16_t opcode;
        size_t   offset;
        size_t   length;
    };
    // What the footer's signature is.
    enum class FooterSignature
    {
        Sign,     // the writer's own
        Copy,     // a rewritten file's signer's, unchanged
        Unsigned, // the signer never signed the end
    };

    // A rewrite: the header and blocks as given, written unchanged.
    Writer(const std::filesystem::path& path, FramePolicy policy, std::vector<uint8_t> header, std::vector<std::vector<uint8_t>> blocks, const SecretSeed* signer);
    auto               open(const std::filesystem::path& path) -> void;
    auto               add(uint64_t timestamp, uint16_t flags, uint8_t channel, uint16_t opcode, std::span<const uint8_t> data) -> void;
    auto               queueMarker(MarkerKind kind, std::string_view text) -> void;
    auto               emit(std::span<const uint8_t> block) -> void;
    auto               writeStart() -> void;
    auto               writeFooter() -> void;
    auto               endFrame(bool last) -> void;
    auto               writeFrame(bool last) -> void;
    auto               usable() const -> void;
    auto               compress(std::span<const uint8_t> plain, bool endStream) -> size_t;
    auto               checkpoint() -> void;
    auto               writeCheckpoint(const CheckpointPayload& payload) -> void;
    [[nodiscard]] auto packetCost(uint64_t timestamp, uint16_t flags, uint8_t channel, uint16_t opcode, size_t length) const -> size_t;
    [[nodiscard]] auto shouldEndFrame(uint64_t timestamp, size_t added) const noexcept -> bool;
    [[nodiscard]] auto checkpoints() const noexcept -> bool
    {
        return policy_.checkpointIntervalMs != 0 && key_ != nullptr;
    }

    std::ofstream file_;
    WriterConfig  config_;
    FramePolicy   policy_;
    CaptureId     captureId_{};
    bool          started_{ false };
    bool          closed_{ false };
    bool          failed_{ false }; // a write failed: no footer may follow
    uint64_t      offset_{ 0 };

    std::vector<ExtensionBlock>       extensions_;
    std::vector<uint8_t>              headerBytes_;
    std::vector<std::vector<uint8_t>> blockBytes_;

    std::vector<uint8_t>          frameBytes_;
    std::vector<FramePacket>      framePackets_;
    std::unordered_set<uint32_t>  frameGroups_;
    size_t                        frameSize_{ 0 }; // plaintext, at most
    std::vector<uint8_t>          compressedBuffer_;
    std::vector<uint8_t>          blockBuffer_;
    uint64_t                      frameBaseTimestamp_{ 0 };
    uint64_t                      lastTimestamp_{ 0 };
    uint64_t                      firstTimestamp_{ 0 };
    uint16_t                      currentZoneId_{ 0 };
    std::vector<PendingMarker>    pendingMarkers_;
    std::vector<FrameMarkerEntry> frameMarkers_;
    size_t                        pendingMarkerBytes_{ 0 };
    std::vector<FooterIndexEntry> frameIndex_;

    // The zstd stream: whether the next frame starts one, and its plaintext so far.
    bool   nextRestart_{ true };
    size_t streamPlain_{ 0 };

    // Frames written since the last checkpoint, and the first one's time.
    uint32_t unsignedFrames_{ 0 };
    uint64_t firstUnsignedTimestamp_{ 0 };

    uint64_t totalPackets_{ 0 };
    uint64_t writtenPackets_{ 0 };
    uint32_t totalFrames_{ 0 };
    uint64_t totalUncompressedBytes_{ 0 };
    uint64_t totalCompressedBytes_{ 0 };

    FooterSignature                       footerSignature_{ FooterSignature::Sign };
    Signature                             copiedSignature_{};
    CheckpointPayload                     keptCheckpoint_{}; // a rewrite's kept checkpoint, which its seal covers; zero for none
    std::unique_ptr<internal::SigningKey> sealKey_;
    std::string                           sealAgent_;
    uint64_t                              sealedAt_{ 0 };

    std::unique_ptr<internal::SignedStream>              stream_;
    std::unique_ptr<internal::SigningKey>                key_;
    std::unique_ptr<ZSTD_CCtx_s, void (*)(ZSTD_CCtx_s*)> cctx_;
};

} // namespace xicap
