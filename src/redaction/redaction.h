#pragma once

#include "xicap/enums/chat.h"
#include "xicap/types.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace xicap::redaction
{

// A packet as a writer stores it.
struct StoredPacket
{
    uint16_t               opcode{};
    uint16_t               flags{};
    std::vector<std::byte> data;
};

// Throws Error for a game packet under 4 bytes.
[[nodiscard]] auto apply(const OutPacket& packet, Chat chat) -> StoredPacket;

} // namespace xicap::redaction
