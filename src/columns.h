#pragma once

#include "xicap/types.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <unordered_map>
#include <vector>

// A frame's plaintext: its packets in columns. See FORMAT.md, Frames.
namespace xicap::internal
{

struct FramePacket
{
    uint64_t timestamp{};
    uint16_t flags{};
    uint8_t  channel{};
    uint16_t opcode{};
    size_t   offset{}; // into Frame::bytes
    size_t   length{};
    size_t   firstMarker{}; // into Frame::markers
    size_t   markerCount{};
};

// A frame's packets, with their bytes back to back and the markers before each.
struct Frame
{
    std::vector<uint8_t>     bytes;
    std::vector<FramePacket> packets;
    std::vector<Marker>      markers;

    auto               add(const Packet& packet) -> void;
    auto               clear() noexcept -> void;
    [[nodiscard]] auto data(const FramePacket& packet) const noexcept -> std::span<const uint8_t>;
    [[nodiscard]] auto packet(size_t i) const noexcept -> Packet;
};

// Timestamps must not go backwards or jump more than 2^32 - 1 ms, and game packets must hold their 4-byte header.
[[nodiscard]] auto encodeColumns(const Frame& frame) -> std::vector<uint8_t>;

[[noreturn]] auto badFrame(std::string_view why) -> void;

// Throws Error for a bad plaintext.
auto decodeColumns(std::span<const uint8_t> plain, uint32_t packetCount, uint32_t markerCount, uint64_t baseTimestamp, Frame& out) -> void;

[[nodiscard]] inline auto isGame(uint8_t channel) noexcept -> bool
{
    return channel == static_cast<uint8_t>(Channel::Game);
}

// Packets that share a channel, direction, and opcode are stored together.
[[nodiscard]] inline auto groupKey(const FramePacket& p) noexcept -> uint32_t
{
    return (uint32_t{ p.channel } << 17) | (static_cast<uint32_t>(p.flags & PacketFlag::ClientToServer) << 16) | p.opcode;
}

// Each packet's group, numbered in order of the groups' first packets; returns how many groups there are.
inline auto assignGroups(std::span<const FramePacket> packets, std::vector<uint32_t>& group) -> uint32_t
{
    std::unordered_map<uint32_t, uint32_t> index;
    group.resize(packets.size());
    for (size_t i = 0; i < packets.size(); ++i)
    {
        group[i] = index.try_emplace(groupKey(packets[i]), static_cast<uint32_t>(index.size())).first->second;
    }

    return static_cast<uint32_t>(index.size());
}

} // namespace xicap::internal
