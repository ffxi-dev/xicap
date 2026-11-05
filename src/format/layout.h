#pragma once

#include "bytes/crc32.h"
#include "xicap/metadata.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

// The on-disk layout. See FORMAT.md.
namespace xicap::format
{

inline constexpr std::array<uint8_t, 8> MAGIC{ 0x89, 'X', 'C', 'P', '\r', '\n', 0x1A, '\n' };
inline constexpr uint8_t                VERSION       = 5;
inline constexpr uint32_t               FRAME_MAGIC   = 0x52464358; // "XCFR"
inline constexpr uint32_t               TRAILER_MAGIC = 0x46504358; // "XCPF"

inline constexpr uint32_t BLOCK_SOURCE = 2;

inline constexpr uint32_t MAX_BLOCK_SIZE   = 16 * 1024 * 1024;
inline constexpr uint32_t MAX_PLAIN_SIZE   = 16 * 1024 * 1024;
inline constexpr uint32_t MAX_PAYLOAD_SIZE = 17 * 1024 * 1024;
inline constexpr uint32_t MAX_PACKETS      = 1024 * 1024;
inline constexpr int      MAX_WINDOW_LOG   = 23;

// The game channel's 4-byte packet header: a 9-bit id, a 7-bit size in 4-byte words, and a 16-bit sync counter.
inline constexpr size_t GAME_HEADER_SIZE = 4;

[[nodiscard]] inline auto gameId(const std::span<const uint8_t> packet) noexcept -> uint16_t
{
    return bytes::load<uint16_t>(packet) & 0x1FFU;
}

// The packet length the header's size gives.
[[nodiscard]] inline auto gameLength(const std::span<const uint8_t> packet) noexcept -> size_t
{
    return static_cast<size_t>(bytes::load<uint16_t>(packet) >> 9U) * 4;
}

[[nodiscard]] inline auto holdsGameHeader(const std::span<const uint8_t> packet, const uint16_t opcode) noexcept -> bool
{
    return packet.size() >= GAME_HEADER_SIZE && gameId(packet) == opcode;
}

#pragma pack(push, 1)

struct Header
{
    std::array<uint8_t, 8> magic;
    uint8_t                version;
    Origin                 origin;
    ServerKind             serverKind;
    uint8_t                blockCount;
    CaptureId              captureId;
    CaptureId              previousCaptureId;
    uint64_t               startTimestamp;
    std::array<char, 32>   captureAgent;
    std::array<char, 32>   clientVersion;
    uint32_t               contentId;
    uint32_t               characterId;
    std::array<char, 16>   characterName;
    std::array<char, 16>   worldName;
    uint32_t               crc;
};
static_assert(sizeof(Header) == HEADER_SIZE);

// Followed by length bytes of payload, then a CRC of both.
struct BlockHeader
{
    uint32_t type;
    uint32_t length;
};

// Followed by the metadata, to the end of the payload.
struct SourceHeader
{
    std::array<char, 16> format;
    std::array<char, 16> formatVersion;
    uint32_t             skippedRecords;
};
static_assert(sizeof(SourceHeader) == 36);

// Followed by payloadSize bytes of payload, then a CRC of both.
struct FrameHeader
{
    uint32_t magic;
    uint32_t payloadSize;
    uint32_t plainSize;
    uint32_t packetCount;
    uint32_t markerCount;
    uint64_t baseTimestamp;
};
static_assert(sizeof(FrameHeader) == 28);

struct Trailer
{
    uint32_t magic;
    uint64_t endTimestamp;
    uint64_t packetCount;
    uint32_t crc;
};
static_assert(sizeof(Trailer) == 24);

#pragma pack(pop)

// The trailer at the start of raw, if its magic and CRC hold.
[[nodiscard]] inline auto readTrailer(const std::span<const uint8_t> raw) noexcept -> std::optional<Trailer>
{
    if (raw.size() < sizeof(Trailer))
    {
        return std::nullopt;
    }

    const auto t = bytes::load<Trailer>(raw);
    if (t.magic != TRAILER_MAGIC || !bytes::endsWithCrc(raw.first(sizeof(Trailer))))
    {
        return std::nullopt;
    }

    return t;
}

} // namespace xicap::format
