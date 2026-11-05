#include "frame/frame.h"

#include <algorithm>

namespace xicap::frame
{

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
    std::ranges::copy(packet.data, std::as_writable_bytes(std::span{ bytes }).subspan(packets.back().offset).begin());
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

auto Frame::packet(const size_t i) const noexcept -> Packet
{
    const auto& p = packets[i];
    return {
        .timestamp = p.timestamp,
        .flags     = p.flags,
        .channel   = p.channel,
        .opcode    = p.opcode,
        .data      = std::as_bytes(data(p)),
        .markers   = std::span{ markers }.subspan(p.firstMarker, p.markerCount),
    };
}

} // namespace xicap::frame
