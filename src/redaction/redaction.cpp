#include "xicap/redaction.h"
#include "format/layout.h"

#include <algorithm>
#include <array>

namespace xicap
{
namespace
{

struct ChatText
{
    PacketDirection direction;
    uint16_t        opcode;
    size_t          offset;
    size_t          length;
};

constexpr auto TO_END = SIZE_MAX;

// After atom0s's XiPackets. Offsets count the 4-byte header.
constexpr auto CHAT_TEXT = std::array{
    ChatText{ .direction = PacketDirection::ServerToClient, .opcode = 0x017, .offset = 0x17, .length = TO_END }, // chat
    ChatText{ .direction = PacketDirection::ClientToServer, .opcode = 0x0B5, .offset = 0x06, .length = TO_END }, // chat
    ChatText{ .direction = PacketDirection::ClientToServer, .opcode = 0x0B6, .offset = 0x15, .length = TO_END }, // tell
    ChatText{ .direction = PacketDirection::ClientToServer, .opcode = 0x0B7, .offset = 0x15, .length = TO_END }, // Assist Channel
    ChatText{ .direction = PacketDirection::ServerToClient, .opcode = 0x0CC, .offset = 0x08, .length = 128 },    // linkshell message board
    ChatText{ .direction = PacketDirection::ClientToServer, .opcode = 0x0E2, .offset = 0x10, .length = 128 },    // linkshell message board post
};

} // namespace

auto redact(const std::span<uint8_t> packet, const PacketDirection direction) -> bool
{
    if (packet.size() < format::GAME_HEADER_SIZE)
    {
        return false;
    }

    const auto opcode = format::gameId(packet);
    const auto text   = std::ranges::find_if(CHAT_TEXT, [&](const ChatText& t)
                                             {
                                               return t.direction == direction && t.opcode == opcode;
                                             });
    if (text == CHAT_TEXT.end())
    {
        return false;
    }

    if (text->offset < packet.size())
    {
        std::fill_n(packet.begin() + static_cast<ptrdiff_t>(text->offset), std::min(text->length, packet.size() - text->offset), uint8_t{ 0 });
    }

    return true;
}

} // namespace xicap
