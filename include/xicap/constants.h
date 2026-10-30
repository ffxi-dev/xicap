#pragma once

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>

static_assert(std::endian::native == std::endian::little,
              "xicap on-disk format is little-endian");

namespace xicap
{

// 89 'X' 'C' 'P' \r \n ^Z \n, after PNG's pattern. See FORMAT.md.
inline constexpr std::array<uint8_t, 8> MAGIC{ 0x89, 'X', 'C', 'P', '\r', '\n', 0x1A, '\n' };
inline constexpr uint32_t               FRAME_MAGIC  = 0x52464358; // 'XCFR'
inline constexpr uint32_t               FOOTER_MAGIC = 0x46504358; // 'XCPF'

inline constexpr uint8_t VERSION_MAJOR = 3;
inline constexpr uint8_t VERSION_MINOR = 0;

inline constexpr uint16_t HEADER_SIZE     = 384;
inline constexpr uint16_t HEADER_SIZE_MAX = 4096;

namespace FrameLimits
{
// Writer defaults for ending a frame.
inline constexpr size_t   MAX_COMPRESSED_SIZE = 64 * 1024;
inline constexpr uint32_t MAX_PACKET_COUNT    = 1000;
inline constexpr uint64_t MAX_TIME_WINDOW_MS  = 5000;
// Hard limits from FORMAT.md.
inline constexpr uint64_t MAX_CONTENT_SIZE   = 16 * 1024 * 1024;
inline constexpr uint32_t MAX_PACKETS        = UINT16_MAX;
inline constexpr uint32_t MAX_EXTENSION_SIZE = 16 * 1024 * 1024;
} // namespace FrameLimits

inline constexpr uint64_t CHECKPOINT_INTERVAL_MS = 60'000;

namespace FFXIPacket
{
inline constexpr uint16_t LOGIN_ZONE = 0x000A;
inline constexpr uint16_t LOGOUT     = 0x000B;
} // namespace FFXIPacket

#pragma pack(push, 1)
// FFXI packet header. First word: opcode (9 bits) + size (7 bits, in 4-byte
// words). sync is a per-direction sequence counter.
struct FFXIPacketHeader
{
    uint16_t id : 9;
    uint16_t size : 7;
    uint16_t sync;
};
static_assert(sizeof(FFXIPacketHeader) == 4);
#pragma pack(pop)

} // namespace xicap
