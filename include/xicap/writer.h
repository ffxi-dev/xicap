#pragma once

#include "constants.h"
#include "dictionary.h"
#include "types.h"

#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <span>
#include <string>

struct ZSTD_CCtx_s;

namespace xicap
{

// Per-capture metadata. Fields are written into the file Header.
struct WriterConfig
{
    std::string   clientVersion;
    std::string   captureAgent;
    uint16_t      startZoneId{};
    LobbyIdentity lobby{};
    uint8_t       startWeather{};
};

// Frame buffering / compression knobs. Defaults are reasonable for FFXI.
struct FramePolicy
{
    size_t   maxFrameSize       = FrameLimits::MAX_COMPRESSED_SIZE;
    uint32_t maxPacketsPerFrame = FrameLimits::MAX_PACKET_COUNT;
    uint64_t maxFrameTimeMs     = FrameLimits::MAX_TIME_WINDOW_MS;
    int      compressionLevel   = 12;

    // Dictionary used to compress frames. A copy is embedded in the capture so
    // readers never need a matching build. Empty disables dictionary use.
    std::span<const uint8_t> dictionary = builtinDictionary();
};

// Hook for extracting the current zone id from a server-to-client packet body.
// Default implementation parses the FFXI GP_SERV_LOGIN packet.
using ZoneIdExtractor = std::function<uint16_t(std::span<const std::byte>)>;

class Writer
{
public:
    Writer(const std::filesystem::path& path, WriterConfig config, FramePolicy policy = {});
    ~Writer();

    Writer(const Writer&)                    = delete;
    Writer(Writer&&)                         = delete;
    auto operator=(const Writer&) -> Writer& = delete;
    auto operator=(Writer&&) -> Writer&      = delete;

    // Must be called before the first packet is written.
    auto addExtension(uint32_t type, std::span<const std::byte> data) -> void;

    auto setZoneExtractor(ZoneIdExtractor extractor) -> void;

    // data must include the 4-byte FFXI header.
    auto write(uint64_t timestamp, PacketDirection direction, std::span<const std::byte> data) -> void;

    // Attach a marker to the most recently written packet in the current frame.
    auto addMarker(std::string_view text) -> void;

    auto flush() -> void;
    auto close() -> void;

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
    [[nodiscard]] auto bytesWritten() -> uint64_t;

private:
    [[nodiscard]] auto extensionCount() const noexcept -> uint16_t;
    auto               writeHeader() -> void;
    auto               writeExtensions() -> void;
    auto               writeFooter() -> void;
    auto               flushFrame() -> void;
    [[nodiscard]] auto shouldFlush(uint64_t nextTimestamp) const noexcept -> bool;

    std::vector<char> writeBuf_;
    std::ofstream     file_;
    WriterConfig      config_;
    FramePolicy       policy_;
    bool              headerWritten_{ false };
    bool              extensionsWritten_{ false };
    bool              closed_{ false };

    std::vector<ExtensionBlock> extensions_;
    std::vector<uint8_t>        dictionary_;
    uint32_t                    dictionaryId_{ 0 };

    std::vector<uint8_t> frameBuffer_;
    std::vector<uint8_t> compressedBuffer_;
    uint64_t             frameBaseTimestamp_ = 0;
    uint64_t             frameLastTimestamp_ = 0;
    uint32_t             framePacketCount_   = 0;
    uint16_t             currentZoneId_;

    struct PendingMarker
    {
        uint16_t    packetIndex;
        std::string text;
    };
    std::vector<PendingMarker>    pendingMarkers_;
    std::vector<FooterIndexEntry> frameIndex_;

    uint64_t totalPackets_           = 0;
    uint32_t totalFrames_            = 0;
    uint64_t totalUncompressedBytes_ = 0;
    uint64_t totalCompressedBytes_   = 0;

    std::unique_ptr<ZSTD_CCtx_s, void (*)(ZSTD_CCtx_s*)> cctx_;
    ZoneIdExtractor                                      zoneExtractor_;
};

} // namespace xicap
