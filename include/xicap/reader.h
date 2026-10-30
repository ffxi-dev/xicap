#pragma once

#include "constants.h"
#include "types.h"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>

struct ZSTD_DCtx_s;

namespace xicap
{

struct ZoneEntry
{
    uint16_t zoneId;
    uint64_t timestamp;
    uint64_t fileOffset;
};

struct ReaderOptions
{
    // Skip damaged frames and go on from the next intact one, instead of
    // refusing a complete file or ending a cut-off one. For salvage only.
    bool recovery = false;
};

struct SkippedRegion
{
    uint64_t offset;
    uint64_t length;
};

// What the signatures prove. See FORMAT.md, Signatures.
struct Verification
{
    PublicKey key{};
    // The footer's signature verifies: every byte is as the recorder wrote it.
    bool signedToEnd{ false };
    // Packets covered by the last signature that verifies.
    uint64_t verifiedPackets{ 0 };
    uint32_t goodCheckpoints{ 0 };
    // First frame whose stored chain value or signature fails, if any.
    std::optional<uint64_t> firstFailureOffset;
};

class Reader
{
public:
    explicit Reader(const std::filesystem::path& path, ReaderOptions options = {});
    ~Reader();

    Reader(const Reader&)                    = delete;
    Reader(Reader&&)                         = delete;
    auto operator=(const Reader&) -> Reader& = delete;
    auto operator=(Reader&&) -> Reader&      = delete;

    [[nodiscard]] auto versionMajor() const noexcept -> uint8_t
    {
        return header_.versionMajor;
    }
    [[nodiscard]] auto versionMinor() const noexcept -> uint8_t
    {
        return header_.versionMinor;
    }
    [[nodiscard]] auto clientVersion() const -> std::string;
    [[nodiscard]] auto captureAgent() const -> std::string;
    [[nodiscard]] auto captureId() const noexcept -> const CaptureId&
    {
        return header_.captureId;
    }
    [[nodiscard]] auto previousCaptureId() const noexcept -> const CaptureId&
    {
        return header_.previousCaptureId;
    }
    [[nodiscard]] auto startTimestamp() const noexcept -> uint64_t
    {
        return header_.startTimestamp;
    }
    [[nodiscard]] auto clockSource() const noexcept -> ClockSource
    {
        return header_.clockSource;
    }
    [[nodiscard]] auto origin() const noexcept -> Origin
    {
        return header_.origin;
    }
    [[nodiscard]] auto network() const noexcept -> Network
    {
        return header_.network;
    }
    [[nodiscard]] auto startContext() const noexcept -> StartContext
    {
        return header_.startContext;
    }
    [[nodiscard]] auto character() const noexcept -> const CharacterIdentity&
    {
        return header_.character;
    }
    [[nodiscard]] auto signingKey() const noexcept -> const PublicKey&
    {
        return header_.signingKey;
    }

    // True when the file ends with a valid footer. False means cut off: the
    // recorder crashed or is still recording.
    [[nodiscard]] auto complete() const noexcept -> bool
    {
        return complete_;
    }
    // The last 4 bytes are the footer magic, but the footer is not valid.
    [[nodiscard]] auto footerDamaged() const noexcept -> bool
    {
        return footerDamaged_;
    }
    // From the footer; 0 when cut off.
    [[nodiscard]] auto endTimestamp() const noexcept -> uint64_t
    {
        return complete_ ? trailer_.endTimestamp : 0;
    }
    [[nodiscard]] auto totalPacketCount() const noexcept -> uint64_t
    {
        return complete_ ? trailer_.totalPacketCount : 0;
    }
    // In a cut-off file read normally: bytes after the last intact frame.
    [[nodiscard]] auto unreadBytes() const noexcept -> uint64_t
    {
        return unreadBytes_;
    }
    // A zone-in read so far names a character other than the header's. Known
    // for the whole capture once every packet has been read.
    [[nodiscard]] auto characterMismatch() const noexcept -> bool
    {
        return characterMismatch_;
    }
    // In recovery mode: damaged regions skipped so far.
    [[nodiscard]] auto skippedRegions() const -> std::vector<SkippedRegion>;

    [[nodiscard]] auto policy() const noexcept -> const ExclusionPolicy&
    {
        return policy_;
    }
    [[nodiscard]] auto source() const noexcept -> const std::optional<SourceInfo>&
    {
        return source_;
    }
    // Blocks other than the dictionary, policy, and source.
    [[nodiscard]] auto extensions() const noexcept -> const std::vector<ExtensionBlock>&
    {
        return extensions_;
    }
    [[nodiscard]] auto getExtension(uint32_t type) const noexcept -> const ExtensionBlock*;

    // Yields the next packet; false at the end of the capture. Throws
    // xicap::Error when the file must be refused.
    auto next(ReadPacket& packet) -> bool;
    auto skipCurrentFrame() noexcept -> void;
    auto reset() -> void;

    auto seekToTime(uint64_t timestamp) -> SeekResult;
    auto seekToZone(uint16_t zoneId) -> SeekResult;
    auto seekToFrame(uint64_t frameIndex) -> SeekResult;

    // Index of the packet frame being read, among packet frames.
    [[nodiscard]] auto currentFrameIndex() const noexcept -> uint64_t
    {
        return currentFrameIndex_;
    }
    [[nodiscard]] auto frameTimestamp(uint64_t frameIndex) const -> uint64_t;
    [[nodiscard]] auto frameZone(uint64_t frameIndex) const -> uint16_t
    {
        return frameIndex < indexEntries_.size() ? indexEntries_[frameIndex].zoneId : 0;
    }
    [[nodiscard]] auto listZones() const -> std::vector<ZoneEntry>;
    [[nodiscard]] auto totalFrames() const noexcept -> uint64_t
    {
        return indexEntries_.size();
    }
    [[nodiscard]] auto durationMs() const -> uint64_t;

    // Recomputes the hash chain over the whole file and checks every
    // signature. Independent of iteration.
    [[nodiscard]] auto verify() -> Verification;

    class Iterator
    {
    public:
        using iterator_category = std::input_iterator_tag;
        using value_type        = ReadPacket;
        using difference_type   = std::ptrdiff_t;
        using pointer           = const ReadPacket*;
        using reference         = const ReadPacket&;

        Iterator() = default;
        explicit Iterator(Reader* reader);

        auto operator*() const noexcept -> reference
        {
            return current_;
        }
        auto operator->() const noexcept -> pointer
        {
            return &current_;
        }
        auto operator++() -> Iterator&;
        auto operator++(int) -> Iterator;

        auto operator==(const Iterator& other) const noexcept -> bool
        {
            return atEnd_ == other.atEnd_;
        }
        auto operator!=(const Iterator& other) const noexcept -> bool
        {
            return !(*this == other);
        }

    private:
        Reader*    reader_ = nullptr;
        ReadPacket current_{};
        bool       atEnd_ = true;
    };

    auto begin() -> Iterator
    {
        return Iterator(this);
    }
    auto end() -> Iterator
    {
        return Iterator();
    }

private:
    struct RawFrame
    {
        FrameHeader          header{};
        std::vector<uint8_t> payload;
        uint32_t             crc{};
    };
    struct DecodedPacket
    {
        PacketEntry entry;
        uint64_t    timestamp;
        size_t      dataOffset;
        size_t      firstMarker;
        size_t      markerCount;
    };

    auto readHeader() -> void;
    auto readExtensions() -> void;
    auto readFooter() -> void;
    auto scanCutOff() -> void;
    auto readRawFrame(uint64_t offset, uint64_t limit, RawFrame& out) -> bool;
    auto resync(uint64_t from, uint64_t limit) -> std::optional<uint64_t>;
    auto advance() -> bool;
    auto decodeFrame(const RawFrame& frame) -> void;
    auto checkCharacter(const PacketEntry& entry, std::span<const uint8_t> data) -> void;

    std::ifstream        file_;
    ReaderOptions        options_;
    uint64_t             fileSize_{ 0 };
    Header               header_{};
    std::vector<uint8_t> headerBytes_;
    uint64_t             dataStart_{ 0 };
    uint64_t             endOffset_{ 0 };

    ExclusionPolicy             policy_;
    std::optional<SourceInfo>   source_;
    std::vector<ExtensionBlock> extensions_;

    bool                          complete_{ false };
    bool                          footerDamaged_{ false };
    FooterTrailer                 trailer_{};
    std::vector<FooterIndexEntry> indexEntries_;
    uint64_t                      unreadBytes_{ 0 };
    bool                          characterMismatch_{ false };
    std::map<uint64_t, uint64_t>  skipped_;

    RawFrame                   raw_;
    std::vector<uint8_t>       frameData_;
    std::vector<DecodedPacket> packets_;
    std::vector<ReadMarker>    markers_;
    size_t                     packetPos_{ 0 };
    uint64_t                   nextOffset_{ 0 };
    uint64_t                   currentFrameIndex_{ 0 };

    std::unique_ptr<ZSTD_DCtx_s, void (*)(ZSTD_DCtx_s*)> dctx_;
};

} // namespace xicap
