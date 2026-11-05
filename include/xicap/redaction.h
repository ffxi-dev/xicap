#pragma once

#include "enums/chat.h"
#include "types.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace xicap
{

struct StoredPacket
{
    uint16_t               opcode{};
    uint16_t               flags{};
    std::vector<std::byte> data;
};

// The packet as a writer stores it: chat text zeroed unless chat is kept. See FORMAT.md, Redaction. Throws Error for a
// game packet under 4 bytes.
[[nodiscard]] auto redact(const OutPacket& packet, Chat chat) -> StoredPacket;

} // namespace xicap
