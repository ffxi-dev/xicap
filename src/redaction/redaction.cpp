#include "xicap/redaction.h"
#include "format/layout.h"
#include "frame/frame.h"

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
    ChatText{ PacketDirection::ServerToClient, 0x017, 0x17, TO_END }, // chat
    ChatText{ PacketDirection::ClientToServer, 0x0B5, 0x06, TO_END }, // chat
    ChatText{ PacketDirection::ClientToServer, 0x0B6, 0x15, TO_END }, // tell
    ChatText{ PacketDirection::ClientToServer, 0x0B7, 0x15, TO_END }, // Assist Channel
    ChatText{ PacketDirection::ServerToClient, 0x0CC, 0x08, 128 },    // linkshell message board
    ChatText{ PacketDirection::ClientToServer, 0x0E2, 0x10, 128 },    // linkshell message board post
};

} // namespace

auto redact(const OutPacket& packet, const Chat chat) -> StoredPacket
{
    auto stored = StoredPacket{
        .opcode = packet.opcode,
        .flags  = static_cast<uint16_t>((packet.provenance & PacketFlag::Provenance) | static_cast<uint16_t>(packet.direction)),
        .data   = { packet.data.begin(), packet.data.end() },
    };
    if (!frame::isGame(packet.channel))
    {
        return stored;
    }

    if (packet.data.size() < format::GAME_HEADER_SIZE)
    {
        throw Error("xicap: a game packet is at least 4 bytes");
    }

    stored.opcode   = format::gameId(packet.data);
    const auto text = std::ranges::find_if(CHAT_TEXT, [&](const ChatText& t)
                                           {
                                               return t.direction == packet.direction && t.opcode == stored.opcode;
                                           });
    if (chat == Chat::Keep || text == CHAT_TEXT.end())
    {
        return stored;
    }

    if (text->offset < stored.data.size())
    {
        std::fill_n(stored.data.begin() + static_cast<ptrdiff_t>(text->offset), std::min(text->length, stored.data.size() - text->offset), std::byte{ 0 });
    }

    stored.flags |= PacketFlag::Redacted;
    return stored;
}

} // namespace xicap
