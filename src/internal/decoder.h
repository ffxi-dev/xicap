#pragma once

#include "internal/columns.h"
#include "xicap/constants.h"
#include "xicap/types.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

struct ZSTD_DCtx_s;

// What Reader, StreamReader, and verification share: the header, the blocks, and a frame decoder.
namespace xicap::internal
{

// zstd's output can exceed its input slightly; a payload past this is garbage.
inline constexpr uint64_t MAX_PAYLOAD_SIZE = FrameLimits::MAX_CONTENT_SIZE + 1024 * 1024;

// A frame's header.
struct FrameInfo
{
    FrameKind kind{};
    uint8_t   frameFlags{};
    uint16_t  markerCount{};
    uint32_t  payloadSize{};
    uint32_t  packetCount{};
    uint64_t  baseTimestamp{};
    uint16_t  zoneId{};
    uint32_t  plainSize{};

    [[nodiscard]] auto restart() const noexcept -> bool
    {
        return (frameFlags & FrameFlag::Restart) != 0;
    }
};

// From sizeof(FrameHeader) bytes. False when the magic is not XCFR.
[[nodiscard]] auto parseFrameHeader(std::span<const uint8_t> bytes, FrameInfo& out) noexcept -> bool;

// Kinds from 0x80 up must be understood; throws UnknownFrameKind for one this library does not know.
auto checkKind(FrameKind kind) -> void;

// The header and extension blocks, as read.
struct Start
{
    Header                            header{};
    std::vector<uint8_t>              headerBytes;
    std::vector<std::vector<uint8_t>> blocks; // each from type to crc, in file order
    ExclusionPolicy                   policy;
    std::optional<SourceInfo>         source;
    std::vector<ExtensionBlock>       extensions; // blocks other than the policy and source
    bool                              havePolicy{ false };
};

// From the first HEADER_SIZE bytes: checks the magic, the version, and the header's size, and returns that size.
auto headerSize(std::span<const uint8_t> first) -> uint16_t;
// From the whole header: checks its CRC and keeps it.
auto readHeader(std::span<const uint8_t> header, Start& start) -> void;
// The whole block's size, from its first 8 bytes.
auto blockSize(std::span<const uint8_t> first) -> uint64_t;
// One whole block, the index-th.
auto readBlock(std::span<const uint8_t> block, uint32_t index, Start& start) -> void;
// After the last block: what must be there is.
auto finishBlocks(Start& start) -> void;

// Whether a decoded game packet is a zone-in naming a character other than the header's.
[[nodiscard]] auto namesOtherCharacter(const Header& header, const DecodedPacket& packet, std::span<const uint8_t> data) -> bool;

// Decodes packet frames in file order, keeping the zstd stream across frames.
class Decoder
{
public:
    Decoder();
    ~Decoder();

    Decoder(const Decoder&)                    = delete;
    Decoder(Decoder&&)                         = delete;
    auto operator=(const Decoder&) -> Decoder& = delete;
    auto operator=(Decoder&&) -> Decoder&      = delete;

    // Throws Error for a bad frame; UnknownPacketFlag for a flag that must be understood.
    auto decode(const FrameInfo& frame, std::span<const uint8_t> payload, DecodedFrame& out) -> void;
    // Forgets the stream: the next packet frame must start one.
    auto reset() noexcept -> void
    {
        streamOpen_    = false;
        lastTimestamp_ = 0;
    }

private:
    auto decodeStream(const FrameInfo& frame, std::span<const uint8_t> payload, DecodedFrame& out) -> void;

    bool                                                 streamOpen_{ false };
    uint64_t                                             lastTimestamp_{ 0 }; // the last packet decoded; 0 after a reset
    std::vector<uint8_t>                                 plain_;
    std::unique_ptr<ZSTD_DCtx_s, void (*)(ZSTD_DCtx_s*)> dctx_;
};

} // namespace xicap::internal
