#include "internal/columns.h"
#include "internal/varint.h"

#include "xicap/constants.h"

#include <cstring>
#include <format>
#include <unordered_map>

namespace xicap::internal
{
namespace
{

constexpr uint8_t GAME = static_cast<uint8_t>(Channel::Game);

auto groupKey(uint8_t channel, uint16_t flags, uint16_t opcode) -> uint32_t
{
    return (uint32_t{ channel } << 17) | (static_cast<uint32_t>(flags & PacketFlag::ClientToServer) << 16) | opcode;
}

auto readU16(const uint8_t* p) -> uint16_t
{
    uint16_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

[[noreturn]] auto bad(const char* why) -> void
{
    throw Error(ErrorCode::CorruptFrame, std::format("xicap: bad frame: {}", why));
}

// Assigns each packet its group, in order of the groups' first packets.
template <typename Packets>
auto groupsOf(const Packets& packets, std::vector<uint32_t>& group) -> uint32_t
{
    std::unordered_map<uint32_t, uint32_t> index;
    group.resize(packets.size());
    for (size_t i = 0; i < packets.size(); ++i)
    {
        const auto& p   = packets[i];
        const auto  key = groupKey(p.channel, p.flags, p.opcode);
        group[i]        = index.try_emplace(key, static_cast<uint32_t>(index.size())).first->second;
    }
    return static_cast<uint32_t>(index.size());
}

} // namespace

auto encodeColumns(std::span<const Record> packets, std::span<const MarkerRecord> markers) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    size_t               bytes = 0;
    for (const auto& p : packets)
    {
        bytes += p.data.size();
    }
    out.reserve(bytes + packets.size() * 8 + 16);

    for (size_t i = 0; i < packets.size(); ++i)
    {
        putVarint(out, i == 0 ? 0 : packets[i].timestamp - packets[i - 1].timestamp);
    }
    for (const auto& p : packets)
    {
        putVarint(out, p.flags);
    }
    for (const auto& p : packets)
    {
        putVarint(out, p.channel);
    }
    for (const auto& p : packets)
    {
        putVarint(out, p.opcode);
    }
    for (const auto& p : packets)
    {
        const bool implied = p.channel == GAME && p.data.size() >= 4 && (readU16(p.data.data()) >> 9) != 0 &&
                             p.data.size() == static_cast<size_t>(readU16(p.data.data()) >> 9U) * 4;
        putVarint(out, implied ? 0 : uint64_t{ p.data.size() } + 1);
    }
    uint16_t lastSync[2] = {};
    for (const auto& p : packets)
    {
        if (p.channel == GAME)
        {
            const auto dir  = p.flags & PacketFlag::ClientToServer;
            const auto sync = readU16(p.data.data() + 2);
            putVarint(out, zigzag16(static_cast<int16_t>(static_cast<uint16_t>(sync - lastSync[dir]))));
            lastSync[dir] = sync;
        }
    }
    for (const auto& m : markers)
    {
        putVarint(out, m.packetIndex);
        out.push_back(static_cast<uint8_t>(m.kind));
        putVarint(out, m.text.size());
        out.insert(out.end(), m.text.begin(), m.text.end());
    }

    std::vector<uint32_t> group;
    const auto            groupCount = groupsOf(packets, group);
    std::vector<uint64_t> sizes(groupCount);
    for (size_t i = 0; i < packets.size(); ++i)
    {
        sizes[group[i]] += packets[i].data.size();
    }
    for (const auto size : sizes)
    {
        putVarint(out, size);
    }
    std::vector<std::vector<uint32_t>> members(groupCount);
    for (size_t i = 0; i < packets.size(); ++i)
    {
        members[group[i]].push_back(static_cast<uint32_t>(i));
    }
    for (const auto& list : members)
    {
        for (const auto i : list)
        {
            const auto& p     = packets[i];
            const auto  start = out.size();
            out.insert(out.end(), p.data.begin(), p.data.end());
            if (p.channel == GAME)
            {
                out[start + 2] = 0;
                out[start + 3] = 0;
            }
        }
    }
    return out;
}

auto decodeColumns(std::span<const uint8_t> plain, uint32_t packetCount, uint16_t markerCount, uint64_t baseTimestamp, DecodedFrame& out) -> void
{
    out.clear();
    // Each packet takes at least one byte in each of sections 1 to 5.
    if (packetCount == 0 || uint64_t{ packetCount } * 5 > plain.size())
    {
        bad("packet count does not fit the plaintext");
    }
    size_t pos    = 0;
    auto   column = [&](unsigned bits, std::vector<uint32_t>& values, size_t count)
    {
        values.resize(count);
        for (auto& v : values)
        {
            if (!getVarint(plain, pos, bits, v))
            {
                bad("bad varint");
            }
        }
    };
    std::vector<uint32_t> delta, flags, channel, opcode, lengths, sync;
    column(32, delta, packetCount);
    if (delta[0] != 0)
    {
        bad("the first packet's deltaMs is not 0");
    }
    column(16, flags, packetCount);
    for (const auto f : flags)
    {
        if ((f & PacketFlag::Required & ~PacketFlag::KnownRequired) != 0)
        {
            throw Error(ErrorCode::UnknownPacketFlag, std::format("xicap: unknown packet flags {:#06x}", f));
        }
    }
    column(8, channel, packetCount);
    column(16, opcode, packetCount);
    column(32, lengths, packetCount);
    size_t games = 0;
    for (const auto c : channel)
    {
        games += c == GAME ? 1 : 0;
    }
    column(16, sync, games);

    std::vector<std::pair<uint32_t, ReadMarker>> markers(markerCount);
    uint32_t                                     lastIndex = 0;
    for (auto& [index, marker] : markers)
    {
        uint32_t textLength = 0;
        if (!getVarint(plain, pos, 32, index) || pos >= plain.size())
        {
            bad("bad marker");
        }
        marker.kind = static_cast<MarkerKind>(plain[pos++]);
        if (!getVarint(plain, pos, 16, textLength) || textLength > plain.size() - pos)
        {
            bad("bad marker");
        }
        if (index >= packetCount || index < lastIndex)
        {
            bad("marker out of place");
        }
        lastIndex = index;
        marker.text.assign(reinterpret_cast<const char*>(plain.data() + pos), textLength);
        pos += textLength;
    }

    struct View
    {
        uint8_t  channel;
        uint16_t flags;
        uint16_t opcode;
    };
    std::vector<View> views(packetCount);
    for (uint32_t i = 0; i < packetCount; ++i)
    {
        views[i] = { static_cast<uint8_t>(channel[i]), static_cast<uint16_t>(flags[i]), static_cast<uint16_t>(opcode[i]) };
    }
    std::vector<uint32_t> group;
    const auto            groupCount = groupsOf(views, group);
    std::vector<uint32_t> sizes;
    column(32, sizes, groupCount);
    std::vector<size_t> cursor(groupCount), end(groupCount);
    uint64_t            total = 0;
    for (uint32_t g = 0; g < groupCount; ++g)
    {
        cursor[g] = pos + total;
        total += sizes[g];
        end[g] = pos + total;
    }
    if (total != plain.size() - pos)
    {
        bad("group sizes do not add up");
    }

    out.bytes.reserve(total);
    out.packets.reserve(packetCount);
    uint64_t timestamp   = baseTimestamp;
    uint16_t lastSync[2] = {};
    size_t   game        = 0;
    size_t   nextMarker  = 0;
    for (uint32_t i = 0; i < packetCount; ++i)
    {
        const auto g      = group[i];
        size_t     length = 0;
        if (channel[i] == GAME)
        {
            if (end[g] - cursor[g] < 4)
            {
                bad("game packet under 4 bytes");
            }
            const auto word = readU16(plain.data() + cursor[g]);
            if ((word & 0x1FFU) != opcode[i])
            {
                bad("game packet opcode differs from its header");
            }
            length = lengths[i] == 0 ? static_cast<size_t>(word >> 9U) * 4 : size_t{ lengths[i] } - 1;
            if (length < 4)
            {
                bad("game packet under 4 bytes");
            }
        }
        else
        {
            if (lengths[i] == 0)
            {
                bad("implied length off the game channel");
            }
            length = size_t{ lengths[i] } - 1;
        }
        if (length > end[g] - cursor[g])
        {
            bad("packet runs past its group");
        }
        const auto offset = out.bytes.size();
        out.bytes.insert(out.bytes.end(), plain.begin() + static_cast<std::ptrdiff_t>(cursor[g]), plain.begin() + static_cast<std::ptrdiff_t>(cursor[g] + length));
        cursor[g] += length;
        if (channel[i] == GAME)
        {
            const auto dir = flags[i] & PacketFlag::ClientToServer;
            lastSync[dir]  = static_cast<uint16_t>(lastSync[dir] + unzigzag16(static_cast<uint16_t>(sync[game++])));
            std::memcpy(out.bytes.data() + offset + 2, &lastSync[dir], sizeof(uint16_t));
        }
        if (timestamp + delta[i] < timestamp)
        {
            bad("a timestamp past 2^64");
        }
        timestamp += delta[i];
        DecodedPacket packet{
            .timestamp   = timestamp,
            .flags       = static_cast<uint16_t>(flags[i]),
            .channel     = static_cast<uint8_t>(channel[i]),
            .opcode      = static_cast<uint16_t>(opcode[i]),
            .offset      = offset,
            .length      = static_cast<uint32_t>(length),
            .firstMarker = out.markers.size(),
            .markerCount = 0,
        };
        while (nextMarker < markers.size() && markers[nextMarker].first == i)
        {
            out.markers.push_back(std::move(markers[nextMarker++].second));
            packet.markerCount++;
        }
        out.packets.push_back(packet);
    }
    for (uint32_t g = 0; g < groupCount; ++g)
    {
        if (cursor[g] != end[g])
        {
            bad("group bytes left over");
        }
    }
}

} // namespace xicap::internal
