#pragma once

#include "constants.h"
#include "types.h"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>

struct ZSTD_DCtx_s;

namespace xicap
{

struct ZoneEntry
{
    uint16_t zoneId;
    uint64_t timestamp;
    uint64_t fileOffset;
};

class Reader
{
public:
    explicit Reader(const std::filesystem::path& path);
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
    [[nodiscard]] auto startZoneId() const noexcept -> uint16_t
    {
        return header_.startZoneId;
    }
    [[nodiscard]] auto startTimestamp() const noexcept -> uint64_t;
    [[nodiscard]] auto endTimestamp() const noexcept -> uint64_t
    {
        return header_.endTimestamp;
    }
    [[nodiscard]] auto endZoneId() const noexcept -> uint16_t
    {
        return header_.endZoneId;
    }
    [[nodiscard]] auto totalPacketCount() const noexcept -> uint64_t
    {
        return header_.totalPacketCount;
    }
    [[nodiscard]] auto lobby() const noexcept -> const LobbyIdentity&
    {
        return header_.lobby;
    }
    [[nodiscard]] auto startWeather() const noexcept -> uint8_t
    {
        return header_.startWeather;
    }

    // True iff the file ended with a valid footer trailer. False indicates the
    // capture was truncated (e.g. game crash); the index was rebuilt by scanning.
    [[nodiscard]] auto hasFooter() const noexcept -> bool
    {
        return hasFooter_;
    }

    [[nodiscard]] auto extensions() const noexcept -> const std::vector<ExtensionBlock>&
    {
        return extensions_;
    }
    // Pointer is valid until the Reader is destroyed.
    [[nodiscard]] auto getExtension(uint32_t type) const noexcept -> const ExtensionBlock*;

    // Yields the next packet. Returns false at end-of-stream. Throws xicap::Error
    // on corrupt frames; callers that wish to skip past a bad frame should catch
    // and call skipCurrentFrame() before continuing.
    //
    // The yielded ReadPacket's data and markers reference internal buffers and
    // are invalidated by the next call to next/seek/reset/destruction.
    auto next(ReadPacket& packet) -> bool;

    // Discard the rest of the current frame so that the next call to next()
    // advances to the next frame.
    auto skipCurrentFrame() noexcept -> void;

    auto reset() -> void;

    auto seekToTime(uint64_t timestamp) -> SeekResult;
    auto seekToZone(uint16_t zoneId) -> SeekResult;
    auto seekToFrame(uint64_t frameIndex) -> SeekResult;

    [[nodiscard]] auto currentFrameIndex() const noexcept -> uint64_t
    {
        return currentFrameIndex_;
    }
    [[nodiscard]] auto frameTimestamp(uint64_t frameIndex) const -> uint64_t;

    [[nodiscard]] auto listZones() const -> std::vector<ZoneEntry>;

    [[nodiscard]] auto totalFrames() const noexcept -> uint64_t
    {
        return indexEntries_.size();
    }
    [[nodiscard]] auto durationMs() const -> uint64_t;

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
    auto readHeader() -> void;
    auto readExtensions() -> void;
    auto loadDictionary() -> void;
    auto loadIndex() -> void;
    auto tryReadFooter() -> bool;
    auto scanFramesForIndex() -> void;
    auto loadFrame(uint64_t offset) -> bool;
    auto readNextFrame() -> bool;
    auto readFrameHeader(FrameHeader& out) -> bool;

    std::ifstream                 file_;
    Header                        header_{};
    std::vector<ExtensionBlock>   extensions_;
    std::vector<FooterIndexEntry> indexEntries_;
    uint64_t                      dataStartOffset_ = 0;
    uint64_t                      fileSize_        = 0;
    bool                          hasFooter_       = false;

    std::vector<uint8_t>                 frameData_;
    std::vector<uint8_t>                 compressedBuffer_;
    std::vector<std::vector<ReadMarker>> framePacketMarkers_;
    size_t                               frameReadPos_          = 0;
    uint32_t                             framePacketsRemaining_ = 0;
    uint32_t                             framePacketIndex_      = 0;
    uint64_t                             currentTimestamp_      = 0;
    uint64_t                             currentFrameIndex_     = 0;
    bool                                 haveLoadedFrame_       = false;

    std::unique_ptr<ZSTD_DCtx_s, void (*)(ZSTD_DCtx_s*)> dctx_;
};

} // namespace xicap
