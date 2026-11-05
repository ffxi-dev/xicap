#include "bytes/varint.h"
#include "format/layout.h"
#include "frame/frame.h"

#include <array>
#include <ranges>

namespace xicap::frame
{
namespace
{

auto storedLength(const std::span<const uint8_t> data, const uint8_t channel) noexcept -> uint64_t
{
    if (isGame(channel) && format::gameLength(data) == data.size())
    {
        return 0;
    }

    return uint64_t{ data.size() } + 1;
}

} // namespace

auto encode(const Frame& frame) -> std::vector<uint8_t>
{
    const auto&          packets = frame.packets;
    std::vector<uint8_t> out;
    auto                 previous = packets.front().timestamp;
    for (const auto& p : packets)
    {
        bytes::putVarint(out, p.timestamp - previous);
        previous = p.timestamp;
    }

    for (const auto& p : packets)
    {
        bytes::putVarint(out, p.flags);
    }

    for (const auto& p : packets)
    {
        bytes::putVarint(out, p.channel);
    }

    for (const auto& p : packets)
    {
        bytes::putVarint(out, p.opcode);
    }

    for (const auto& p : packets)
    {
        bytes::putVarint(out, storedLength(frame.data(p), p.channel));
    }

    std::array<uint16_t, 2> lastSync{};
    for (const auto& p : packets | std::views::filter([](const FramePacket& p)
                                                      {
                                                          return isGame(p.channel);
                                                      }))
    {
        auto&      last = lastSync[p.flags & PacketFlag::ClientToServer];
        const auto sync = bytes::load<uint16_t>(frame.data(p), 2);
        bytes::putVarint(out, bytes::zigzag16(static_cast<uint16_t>(sync - last)));
        last = sync;
    }

    for (size_t i{ 0 }; i < packets.size(); ++i)
    {
        for (const auto& m : std::span{ frame.markers }.subspan(packets[i].firstMarker, packets[i].markerCount))
        {
            bytes::putVarint(out, i);
            out.push_back(static_cast<uint8_t>(m.kind));
            bytes::putVarint(out, m.text.size());
            out.insert(out.end(), m.text.begin(), m.text.end());
        }
    }

    std::vector<uint32_t>            group;
    std::vector<std::vector<size_t>> members(assignGroups(packets, group));
    for (size_t i{ 0 }; i < packets.size(); ++i)
    {
        members[group[i]].push_back(i);
    }

    for (const auto& list : members)
    {
        uint64_t size{ 0 };
        for (const auto i : list)
        {
            size += packets[i].length;
        }

        bytes::putVarint(out, size);
    }

    for (const auto& list : members)
    {
        for (const auto i : list)
        {
            const auto data  = frame.data(packets[i]);
            const auto start = out.size();
            out.insert(out.end(), data.begin(), data.end());
            if (isGame(packets[i].channel))
            {
                out[start + 2] = 0;
                out[start + 3] = 0;
            }
        }
    }

    return out;
}

} // namespace xicap::frame
