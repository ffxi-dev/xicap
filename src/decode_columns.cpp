#include "columns.h"
#include "format.h"
#include "varint.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <ranges>

namespace xicap::internal
{
namespace
{

[[noreturn]] auto bad(std::string_view why) -> void
{
    throw Error(std::format("xicap: bad frame: {}", why));
}

// Reads one column of count varints, each for a field `bits` wide.
auto column(std::span<const uint8_t> plain, size_t& pos, unsigned bits, size_t count) -> std::vector<uint32_t>
{
    std::vector<uint32_t> values(count);
    for (auto& v : values)
    {
        if (!getVarint(plain, pos, bits, v))
        {
            bad("bad varint");
        }
    }

    return values;
}

auto readMarkers(std::span<const uint8_t> plain, size_t& pos, uint32_t count, uint32_t packetCount) -> std::vector<std::pair<uint32_t, Marker>>
{
    std::vector<std::pair<uint32_t, Marker>> markers(count);
    uint32_t                                 lastIndex = 0;
    for (auto& [index, marker] : markers)
    {
        uint32_t length = 0;
        if (!getVarint(plain, pos, 32, index) || pos >= plain.size())
        {
            bad("bad marker");
        }
        marker.kind = static_cast<MarkerKind>(plain[pos++]);
        if (!getVarint(plain, pos, 16, length) || length > plain.size() - pos)
        {
            bad("bad marker");
        }
        if (index >= packetCount || index < lastIndex)
        {
            bad("marker out of place");
        }
        lastIndex = index;
        marker.text.assign(reinterpret_cast<const char*>(plain.data() + pos), length);
        pos += length;
    }

    return markers;
}

} // namespace

auto DecodedFrame::packet(size_t i) const -> Packet
{
    const auto& p = packets[i];
    return {
        .timestamp = p.timestamp,
        .flags     = p.flags,
        .channel   = p.channel,
        .opcode    = p.opcode,
        .data      = std::as_bytes(std::span{ bytes }.subspan(p.offset, p.length)),
        .markers   = std::span{ markers }.subspan(p.firstMarker, p.markerCount),
    };
}

auto decodeColumns(std::span<const uint8_t> plain, uint32_t packetCount, uint32_t markerCount, uint64_t baseTimestamp, DecodedFrame& out) -> void
{
    out.bytes.clear();
    out.packets.clear();
    out.markers.clear();
    // Each packet takes at least one byte in each of the first five columns, and each marker three.
    if (packetCount == 0 || uint64_t{ packetCount } * 5 + uint64_t{ markerCount } * 3 > plain.size())
    {
        bad("packet and marker counts do not fit the plaintext");
    }
    size_t     pos     = 0;
    const auto delta   = column(plain, pos, 32, packetCount);
    const auto flags   = column(plain, pos, 16, packetCount);
    const auto channel = column(plain, pos, 8, packetCount);
    const auto opcode  = column(plain, pos, 16, packetCount);
    const auto lengths = column(plain, pos, 32, packetCount);
    const auto sync    = column(plain, pos, 16, static_cast<size_t>(std::ranges::count(channel, uint32_t{ 0 })));
    auto       markers = readMarkers(plain, pos, markerCount, packetCount);
    if (delta[0] != 0)
    {
        bad("the first packet's deltaMs is not 0");
    }

    std::vector<uint32_t> keys(packetCount);
    for (uint32_t i = 0; i < packetCount; ++i)
    {
        keys[i] = groupKey(static_cast<uint8_t>(channel[i]), static_cast<uint16_t>(flags[i]), static_cast<uint16_t>(opcode[i]));
    }
    std::vector<uint32_t> group;
    const auto            sizes = column(plain, pos, 32, assignGroups(keys, group));
    std::vector<size_t>   cursor(sizes.size());
    std::vector<size_t>   end(sizes.size());
    size_t                at = pos;
    for (size_t g = 0; g < sizes.size(); ++g)
    {
        cursor[g] = at;
        at += sizes[g];
        end[g] = at;
    }
    if (at != plain.size())
    {
        bad("group sizes do not add up");
    }

    out.bytes.reserve(plain.size() - pos);
    out.packets.reserve(packetCount);
    uint64_t                timestamp = baseTimestamp;
    std::array<uint16_t, 2> lastSync{};
    size_t                  game       = 0;
    size_t                  nextMarker = 0;
    for (uint32_t i = 0; i < packetCount; ++i)
    {
        const auto g      = group[i];
        const auto left   = end[g] - cursor[g];
        const auto length = [&]() -> size_t
        {
            if (!isGame(static_cast<uint8_t>(channel[i])))
            {
                if (lengths[i] == 0)
                {
                    bad("implied length off the game channel");
                }
                return size_t{ lengths[i] } - 1;
            }
            if (left < format::GAME_HEADER_SIZE)
            {
                bad("game packet under 4 bytes");
            }
            uint16_t head = 0;
            std::memcpy(&head, plain.data() + cursor[g], sizeof(head));
            if ((head & 0x1FFU) != opcode[i])
            {
                bad("game packet opcode differs from its header");
            }
            if (lengths[i] == 0)
            {
                return static_cast<size_t>(head >> 9U) * 4;
            }
            return size_t{ lengths[i] } - 1;
        }();
        if (length > left || (isGame(static_cast<uint8_t>(channel[i])) && length < format::GAME_HEADER_SIZE))
        {
            bad("packet does not fit its group");
        }
        const auto offset = out.bytes.size();
        out.bytes.insert(out.bytes.end(), plain.begin() + static_cast<std::ptrdiff_t>(cursor[g]), plain.begin() + static_cast<std::ptrdiff_t>(cursor[g] + length));
        cursor[g] += length;
        if (isGame(static_cast<uint8_t>(channel[i])))
        {
            auto& last = lastSync[flags[i] & PacketFlag::ClientToServer];
            last       = static_cast<uint16_t>(last + unzigzag16(static_cast<uint16_t>(sync[game++])));
            std::memcpy(out.bytes.data() + offset + 2, &last, sizeof(last));
        }
        if (timestamp + delta[i] < timestamp)
        {
            bad("a timestamp past 2^64");
        }
        timestamp += delta[i];
        auto packet = DecodedPacket{
            .timestamp   = timestamp,
            .flags       = static_cast<uint16_t>(flags[i]),
            .channel     = static_cast<uint8_t>(channel[i]),
            .opcode      = static_cast<uint16_t>(opcode[i]),
            .offset      = offset,
            .length      = length,
            .firstMarker = out.markers.size(),
            .markerCount = 0,
        };
        for (; nextMarker < markers.size() && markers[nextMarker].first == i; ++nextMarker)
        {
            out.markers.push_back(std::move(markers[nextMarker].second));
            packet.markerCount++;
        }
        out.packets.push_back(packet);
    }
    if (cursor != end)
    {
        bad("group bytes left over");
    }
}

} // namespace xicap::internal
