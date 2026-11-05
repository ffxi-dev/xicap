#include "bytes/varint.h"
#include "format/layout.h"
#include "frame/frame.h"

#include <algorithm>
#include <array>
#include <format>
#include <string_view>

namespace xicap::frame
{

auto bad(const std::string_view why) -> void
{
    throw Error(std::format("xicap: bad frame: {}", why));
}

namespace
{

auto column(const std::span<const uint8_t> plain, size_t& pos, const unsigned bits, const size_t count) -> std::vector<uint32_t>
{
    std::vector<uint32_t> values(count);
    for (auto& v : values)
    {
        if (!bytes::getVarint(plain, pos, bits, v))
        {
            bad("bad varint");
        }
    }

    return values;
}

// Reads the markers into out and returns the packet index of each.
auto readMarkers(const std::span<const uint8_t> plain, size_t& pos, const uint32_t count, const uint32_t packetCount, std::vector<Marker>& out) -> std::vector<uint32_t>
{
    std::vector<uint32_t> indexes(count);
    uint32_t              lastIndex{ 0 };
    for (auto& index : indexes)
    {
        uint32_t length{ 0 };
        if (!bytes::getVarint(plain, pos, 32, index) || pos >= plain.size())
        {
            bad("bad marker");
        }

        const auto kind = static_cast<MarkerKind>(plain[pos++]);
        if (!bytes::getVarint(plain, pos, 16, length) || length > plain.size() - pos)
        {
            bad("bad marker");
        }

        if (index >= packetCount || index < lastIndex)
        {
            bad("marker out of place");
        }

        lastIndex       = index;
        const auto text = plain.subspan(pos, length);
        out.push_back({ .kind = kind, .text = std::string(text.begin(), text.end()) });
        pos += length;
    }

    return indexes;
}

} // namespace

auto decode(const std::span<const uint8_t> plain, const uint32_t packetCount, const uint32_t markerCount, const uint64_t baseTimestamp, Frame& out) -> void
{
    out.clear();
    // Each packet takes at least one byte in each of the first five columns, and each marker three.
    if (packetCount == 0 || uint64_t{ packetCount } * 5 + uint64_t{ markerCount } * 3 > plain.size())
    {
        bad("packet and marker counts do not fit the plaintext");
    }

    size_t     pos{ 0 };
    const auto delta   = column(plain, pos, 32, packetCount);
    const auto flags   = column(plain, pos, 16, packetCount);
    const auto channel = column(plain, pos, 8, packetCount);
    const auto opcode  = column(plain, pos, 16, packetCount);
    const auto lengths = column(plain, pos, 32, packetCount);
    const auto sync    = column(plain, pos, 16, static_cast<size_t>(std::ranges::count(channel, uint32_t{ 0 })));
    const auto marked  = readMarkers(plain, pos, markerCount, packetCount, out.markers);
    if (delta[0] != 0)
    {
        bad("the first packet's deltaMs is not 0");
    }

    out.packets.reserve(packetCount);
    auto timestamp = baseTimestamp;
    for (uint32_t i{ 0 }; i < packetCount; ++i)
    {
        if (timestamp + delta[i] < timestamp)
        {
            bad("a timestamp past 2^64");
        }

        timestamp += delta[i];
        const auto [first, last] = std::ranges::equal_range(marked, i);
        out.packets.push_back({
            .timestamp   = timestamp,
            .flags       = static_cast<uint16_t>(flags[i]),
            .channel     = static_cast<uint8_t>(channel[i]),
            .opcode      = static_cast<uint16_t>(opcode[i]),
            .offset      = 0,
            .length      = 0,
            .firstMarker = static_cast<size_t>(first - marked.begin()),
            .markerCount = static_cast<size_t>(last - first),
        });
    }

    std::vector<uint32_t> group;
    const auto            sizes = column(plain, pos, 32, assignGroups(out.packets, group));
    std::vector<size_t>   cursor(sizes.size());
    std::vector<size_t>   end(sizes.size());
    auto                  at = pos;
    for (size_t g{ 0 }; g < sizes.size(); ++g)
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
    std::array<uint16_t, 2> lastSync{};
    size_t                  game{ 0 };
    for (uint32_t i{ 0 }; i < packetCount; ++i)
    {
        auto&      p      = out.packets[i];
        const auto g      = group[i];
        const auto left   = plain.subspan(cursor[g], end[g] - cursor[g]);
        const auto length = [&]() -> size_t
        {
            if (!isGame(p.channel))
            {
                if (lengths[i] == 0)
                {
                    bad("implied length off the game channel");
                }

                return size_t{ lengths[i] } - 1;
            }

            if (left.size() < format::GAME_HEADER_SIZE)
            {
                bad("game packet under 4 bytes");
            }

            if (format::gameId(left) != p.opcode)
            {
                bad("game packet opcode differs from its header");
            }

            if (lengths[i] == 0)
            {
                return format::gameLength(left);
            }

            return size_t{ lengths[i] } - 1;
        }();
        if (length > left.size() || (isGame(p.channel) && length < format::GAME_HEADER_SIZE))
        {
            bad("packet does not fit its group");
        }

        p.offset = out.bytes.size();
        p.length = length;
        out.bytes.insert(out.bytes.end(), left.begin(), left.begin() + static_cast<std::ptrdiff_t>(length));
        cursor[g] += length;
        if (isGame(p.channel))
        {
            auto& last              = lastSync[p.flags & PacketFlag::ClientToServer];
            last                    = static_cast<uint16_t>(last + bytes::unzigzag16(static_cast<uint16_t>(sync[game++])));
            out.bytes[p.offset + 2] = static_cast<uint8_t>(last);
            out.bytes[p.offset + 3] = static_cast<uint8_t>(last >> 8);
        }
    }

    if (cursor != end)
    {
        bad("group bytes left over");
    }
}

} // namespace xicap::frame
