#include "columns.h"
#include "format.h"
#include "varint.h"

#include <array>
#include <cstring>
#include <ranges>

namespace xicap::internal
{
namespace
{

auto word(std::span<const uint8_t> data, size_t at) -> uint16_t
{
    uint16_t v = 0;
    std::memcpy(&v, data.data() + at, sizeof(v));
    return v;
}

// A game packet whose header's size gives its length stores its length as 0.
auto storedLength(const Record& p) -> uint64_t
{
    if (isGame(p.channel))
    {
        const auto words = word(p.data, 0) >> 9;
        if (words != 0 && p.data.size() == static_cast<size_t>(words) * 4)
        {
            return 0;
        }
    }

    return uint64_t{ p.data.size() } + 1;
}

} // namespace

auto encodeColumns(std::span<const Record> packets, std::span<const MarkerRecord> markers) -> std::vector<uint8_t>
{
    std::vector<uint8_t> out;
    uint64_t             previous = packets.front().timestamp;
    for (const auto& p : packets)
    {
        putVarint(out, p.timestamp - previous);
        previous = p.timestamp;
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
        putVarint(out, storedLength(p));
    }
    std::array<uint16_t, 2> lastSync{};
    for (const auto& p : packets | std::views::filter([](const Record& r)
                                                      {
                                                          return isGame(r.channel);
                                                      }))
    {
        auto&      last = lastSync[p.flags & PacketFlag::ClientToServer];
        const auto sync = word(p.data, 2);
        putVarint(out, zigzag16(static_cast<uint16_t>(sync - last)));
        last = sync;
    }
    for (const auto& m : markers)
    {
        putVarint(out, m.packetIndex);
        out.push_back(static_cast<uint8_t>(m.kind));
        putVarint(out, m.text.size());
        out.insert(out.end(), m.text.begin(), m.text.end());
    }

    std::vector<uint32_t> keys;
    for (const auto& p : packets)
    {
        keys.push_back(groupKey(p.channel, p.flags, p.opcode));
    }
    std::vector<uint32_t>            group;
    std::vector<std::vector<size_t>> members(assignGroups(keys, group));
    for (size_t i = 0; i < packets.size(); ++i)
    {
        members[group[i]].push_back(i);
    }
    for (const auto& list : members)
    {
        uint64_t size = 0;
        for (const auto i : list)
        {
            size += packets[i].data.size();
        }
        putVarint(out, size);
    }
    for (const auto& list : members)
    {
        for (const auto i : list)
        {
            const auto& p     = packets[i];
            const auto  start = out.size();
            out.insert(out.end(), p.data.begin(), p.data.end());
            if (isGame(p.channel))
            {
                out[start + 2] = 0;
                out[start + 3] = 0;
            }
        }
    }

    return out;
}

} // namespace xicap::internal
