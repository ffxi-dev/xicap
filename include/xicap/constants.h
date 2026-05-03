#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>

static_assert(std::endian::native == std::endian::little,
              "xicap on-disk format is little-endian");

namespace xicap
{

inline constexpr uint32_t MAGIC        = 0x50414358; // 'XCAP' little-endian
inline constexpr uint32_t FOOTER_MAGIC = 0x46504358; // 'XCPF' little-endian; absent on truncated captures

inline constexpr uint8_t VERSION_MAJOR = 2;
inline constexpr uint8_t VERSION_MINOR = 0;

namespace FrameLimits
{
inline constexpr size_t   MAX_COMPRESSED_SIZE = 64 * 1024;
inline constexpr uint32_t MAX_PACKET_COUNT    = 1000;
inline constexpr uint64_t MAX_TIME_WINDOW_MS  = 5000;
} // namespace FrameLimits

namespace FFXIPacket
{
inline constexpr uint16_t LOGIN_ZONE = 0x000A;
inline constexpr uint16_t LOGOUT     = 0x000B;
} // namespace FFXIPacket

#pragma pack(push, 1)

// FFXI packet header. First word: opcode (9 bits) + size (7 bits). sync is a
// per-direction sequence counter.
struct FFXIPacketHeader
{
    uint16_t id : 9;
    uint16_t size : 7;
    uint16_t sync;
};
static_assert(sizeof(FFXIPacketHeader) == 4);

#pragma pack(pop)

} // namespace xicap
