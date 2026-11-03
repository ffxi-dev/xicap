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
inline constexpr uint32_t               SEAL_MAGIC   = 0x4C534358; // 'XCSL'

// The version the writer writes. Readers also read format 3 (FORMAT-3.md).
inline constexpr uint8_t VERSION_MAJOR = 4;
inline constexpr uint8_t VERSION_MINOR = 1;

inline constexpr uint16_t HEADER_SIZE     = 384;
inline constexpr uint16_t HEADER_SIZE_MAX = 4096;

namespace FrameLimits
{
// Hard limits from FORMAT.md.
inline constexpr uint64_t MAX_CONTENT_SIZE   = 16 * 1024 * 1024;
inline constexpr uint32_t MAX_PACKETS        = 1024 * 1024;
inline constexpr uint32_t MAX_EXTENSION_SIZE = 16 * 1024 * 1024;
inline constexpr int      MAX_WINDOW_LOG     = 23;
} // namespace FrameLimits

inline constexpr uint64_t CHECKPOINT_INTERVAL_MS = 60'000;

namespace FFXIPacket
{
inline constexpr uint16_t LOGIN_ZONE = 0x000A;
inline constexpr uint16_t LOGOUT     = 0x000B;
// Fields of the zone-in (0x00A, server to client), from LandSandBoat's
// GP_SERV_COMMAND_LOGIN after atom0s's XiPackets. Offsets count the 4-byte
// packet header.
inline constexpr size_t LOGIN_UNIQUE_NO_OFFSET = 4;   // u32: the character's id
inline constexpr size_t LOGIN_ZONE_NO_OFFSET   = 48;  // u32: the zone
inline constexpr size_t LOGIN_NAME_OFFSET      = 132; // char[16]: the character's name
inline constexpr size_t LOGIN_NAME_SIZE        = 16;
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
