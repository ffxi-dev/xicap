#pragma once

#include "enums/packet_direction.h"

#include <cstdint>
#include <span>

namespace xicap
{

// Zeroes the player-written text of a game packet, by FORMAT.md's Redaction table, and returns whether the packet is in
// the table.
auto redact(std::span<uint8_t> packet, PacketDirection direction) -> bool;

} // namespace xicap
