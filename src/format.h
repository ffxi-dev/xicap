#pragma once

#include "bytes.h"
#include "xicap/types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

// The on-disk layout. See FORMAT.md.
namespace xicap::format
{

inline constexpr std::array<uint8_t, 8> MAGIC{ 0x89, 'X', 'C', 'P', '\r', '\n', 0x1A, '\n' };
inline constexpr uint8_t                VERSION       = 5;
inline constexpr uint32_t               FRAME_MAGIC   = 0x52464358; // "XCFR"
inline constexpr uint32_t               TRAILER_MAGIC = 0x46504358; // "XCPF"

inline constexpr uint32_t BLOCK_POLICY = 1;
inline constexpr uint32_t BLOCK_SOURCE = 2;

inline constexpr uint32_t MAX_BLOCK_SIZE   = 16 * 1024 * 1024;
inline constexpr uint32_t MAX_PLAIN_SIZE   = 16 * 1024 * 1024;
inline constexpr uint32_t MAX_PAYLOAD_SIZE = 17 * 1024 * 1024;
inline constexpr uint32_t MAX_PACKETS      = 1024 * 1024;
inline constexpr int      MAX_WINDOW_LOG   = 23;

// The game channel's 4-byte packet header: a 9-bit id, a 7-bit size in 4-byte words, and a 16-bit sync counter.
inline constexpr size_t GAME_HEADER_SIZE = 4;

template <typename Byte>
[[nodiscard]] auto gameId(std::span<Byte> packet) noexcept -> uint16_t
{
    return internal::load<uint16_t>(packet) & 0x1FFU;
}

// The packet length the header's size gives.
template <typename Byte>
[[nodiscard]] auto gameLength(std::span<Byte> packet) noexcept -> size_t
{
    return static_cast<size_t>(internal::load<uint16_t>(packet) >> 9U) * 4;
}

template <size_t N>
using Text = std::array<char, N>;

#pragma pack(push, 1)

struct Header
{
    std::array<uint8_t, 8> magic;
    uint8_t                version;
    Origin                 origin;
    Network                network;
    uint8_t                blockCount;
    CaptureId              captureId;
    CaptureId              previousCaptureId;
    uint64_t               startTimestamp;
    Text<32>               captureAgent;
    Text<32>               clientVersion;
    uint32_t               contentId;
    uint32_t               characterId;
    Text<16>               characterName;
    Text<16>               worldName;
    uint32_t               crc;
};
static_assert(sizeof(Header) == 160);

// Followed by length bytes of payload, then a CRC of both.
struct BlockHeader
{
    uint32_t type;
    uint32_t length;
};

struct PolicyHeader
{
    Text<32> name;
    uint32_t version;
    uint16_t ruleCount;
};
static_assert(sizeof(PolicyHeader) == 38);

// Followed by rangeCount ranges of u32 offset, u32 length.
struct RuleHeader
{
    uint8_t  channel;
    uint8_t  direction;
    uint8_t  action;
    uint16_t opcode;
    uint16_t rangeCount;
};
static_assert(sizeof(RuleHeader) == 7);

// Followed by the metadata, to the end of the payload.
struct SourceHeader
{
    Text<16> format;
    Text<16> formatVersion;
    uint32_t skippedRecords;
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

} // namespace xicap::format
