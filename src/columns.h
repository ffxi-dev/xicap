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

struct Record
{
    uint64_t                 timestamp{};
    uint16_t                 flags{};
    uint8_t                  channel{};
    uint16_t                 opcode{};
    std::span<const uint8_t> data;
};

struct MarkerRecord
{
    uint32_t         packetIndex{};
    MarkerKind       kind{};
    std::string_view text;
};

// Timestamps must not go backwards, deltas must fit 32 bits, game packets must hold their 4-byte header, and markers
// must be in packet order.
[[nodiscard]] auto encodeColumns(std::span<const Record> packets, std::span<const MarkerRecord> markers) -> std::vector<uint8_t>;

struct DecodedPacket
{
    uint64_t timestamp{};
    uint16_t flags{};
    uint8_t  channel{};
    uint16_t opcode{};
    size_t   offset{};
    size_t   length{};
    size_t   firstMarker{};
    size_t   markerCount{};
};

struct DecodedFrame
{
    std::vector<uint8_t>       bytes;
    std::vector<DecodedPacket> packets;
    std::vector<Marker>        markers;

    [[nodiscard]] auto packet(size_t i) const -> Packet;
};

// Throws Error for a bad plaintext.
auto decodeColumns(std::span<const uint8_t> plain, uint32_t packetCount, uint32_t markerCount, uint64_t baseTimestamp, DecodedFrame& out) -> void;

[[nodiscard]] inline auto isGame(uint8_t channel) noexcept -> bool
{
    return channel == static_cast<uint8_t>(Channel::Game);
}

// Packets that share a channel, direction, and opcode are stored together.
[[nodiscard]] inline auto groupKey(uint8_t channel, uint16_t flags, uint16_t opcode) noexcept -> uint32_t
{
    return (uint32_t{ channel } << 17) | (static_cast<uint32_t>(flags & PacketFlag::ClientToServer) << 16) | opcode;
}

// Each packet's group, numbered in order of the groups' first packets; returns how many groups there are.
inline auto assignGroups(std::span<const uint32_t> keys, std::vector<uint32_t>& group) -> uint32_t
{
    std::unordered_map<uint32_t, uint32_t> index;
    group.resize(keys.size());
    for (size_t i = 0; i < keys.size(); ++i)
    {
        group[i] = index.try_emplace(keys[i], static_cast<uint32_t>(index.size())).first->second;
    }

    return static_cast<uint32_t>(index.size());
}

} // namespace xicap::internal
