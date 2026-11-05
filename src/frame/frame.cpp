#include "frame/frame.h"

#include <algorithm>
#include <format>
#include <unordered_map>

namespace xicap::frame
{
namespace
{

// Packets that share a channel, direction, and opcode are stored together.
auto groupKey(const FramePacket& p) noexcept -> uint32_t
{
    return (uint32_t{ static_cast<uint8_t>(p.channel) } << 17) | (static_cast<uint32_t>(p.flags & PacketFlag::ClientToServer) << 16) | p.opcode;
}

} // namespace

auto throwBadFrame(const std::string_view why) -> void
{
    throw Error(std::format("xicap: bad frame: {}", why));
}

auto Frame::add(const Packet& packet) -> void
{
    packets.push_back({
        .timestamp   = packet.timestamp,
        .flags       = packet.flags,
        .channel     = packet.channel,
        .opcode      = packet.opcode,
        .offset      = bytes.size(),
        .length      = packet.data.size(),
        .firstMarker = markers.size(),
        .markerCount = packet.markers.size(),
    });
    bytes.resize(bytes.size() + packet.data.size());
    std::ranges::copy(packet.data, bytes.begin() + static_cast<std::ptrdiff_t>(packets.back().offset));
    markers.insert(markers.end(), packet.markers.begin(), packet.markers.end());
}

auto Frame::clear() noexcept -> void
{
    bytes.clear();
    packets.clear();
    markers.clear();
}

auto Frame::data(const FramePacket& packet) const noexcept -> std::span<const uint8_t>
{
    return std::span{ bytes }.subspan(packet.offset, packet.length);
}

auto Frame::data(const FramePacket& packet) noexcept -> std::span<uint8_t>
{
    return std::span{ bytes }.subspan(packet.offset, packet.length);
}

auto Frame::packet(const size_t i) const noexcept -> Packet
{
    const auto& p = packets[i];
    return {
        .timestamp = p.timestamp,
        .flags     = p.flags,
        .channel   = p.channel,
        .opcode    = p.opcode,
        .data      = data(p),
        .markers   = std::span{ markers }.subspan(p.firstMarker, p.markerCount),
    };
}

auto assignGroups(const std::span<const FramePacket> packets, std::vector<uint32_t>& group) -> uint32_t
{
    std::unordered_map<uint32_t, uint32_t> index;
    group.resize(packets.size());
    for (size_t i{ 0 }; i < packets.size(); ++i)
    {
        group[i] = index.try_emplace(groupKey(packets[i]), static_cast<uint32_t>(index.size())).first->second;
    }

    return static_cast<uint32_t>(index.size());
}

} // namespace xicap::frame
