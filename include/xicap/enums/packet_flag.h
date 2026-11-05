#pragma once

#include <cstdint>

namespace xicap
{

namespace PacketFlag
{
inline constexpr uint16_t ClientToServer = 0x0001;
inline constexpr uint16_t Injected       = 0x0002;
inline constexpr uint16_t Blocked        = 0x0004;
inline constexpr uint16_t Modified       = 0x0008;
inline constexpr uint16_t FirstInChunk   = 0x0010;
inline constexpr uint16_t Provenance     = Injected | Blocked | Modified | FirstInChunk;
inline constexpr uint16_t Excluded       = 0x0100;
inline constexpr uint16_t Redacted       = 0x0200;
} // namespace PacketFlag

} // namespace xicap
