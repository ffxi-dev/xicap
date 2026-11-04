#pragma once

#include "xicap/types.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// A packet frame's plaintext: packets in columns. See FORMAT.md, Packet frames.
namespace xicap::internal
{

// A packet as stored and as the signed stream hashes it.
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

// Packets with the same key share a group: channel, direction, and opcode.
[[nodiscard]] constexpr auto groupKey(uint8_t channel, uint16_t flags, uint16_t opcode) noexcept -> uint32_t
{
    return (uint32_t{ channel } << 17) | (static_cast<uint32_t>(flags & PacketFlag::ClientToServer) << 16) | opcode;
}

// Timestamps must not go backwards; deltas must fit 32 bits; markers must be in packet order.
[[nodiscard]] auto encodeColumns(std::span<const Record> packets, std::span<const MarkerRecord> markers) -> std::vector<uint8_t>;

// A decoded packet: its bytes and markers are ranges of its frame's.
struct DecodedPacket
{
    uint64_t timestamp{};
    uint16_t flags{};
    uint8_t  channel{};
    uint16_t opcode{};
    size_t   offset{};
    uint32_t length{};
    size_t   firstMarker{};
    size_t   markerCount{};
};

struct DecodedFrame
{
    std::vector<uint8_t>       bytes;
    std::vector<DecodedPacket> packets;
    std::vector<ReadMarker>    markers;

    auto clear() -> void
    {
        bytes.clear();
        packets.clear();
        markers.clear();
    }

    // The index-th packet, pointing into this frame.
    [[nodiscard]] auto read(size_t index) const -> ReadPacket
    {
        const auto& p = packets[index];
        return {
            .timestamp = p.timestamp,
            .channel   = p.channel,
            .opcode    = p.opcode,
            .flags     = p.flags,
            .direction = static_cast<PacketDirection>(p.flags & PacketFlag::ClientToServer),
            .data      = std::as_bytes(std::span{ bytes }.subspan(p.offset, p.length)),
            .markers   = std::span{ markers }.subspan(p.firstMarker, p.markerCount),
        };
    }
};

// Throws Error(CorruptFrame) for a bad plaintext and Error(UnknownPacketFlag) for a must-understand flag.
auto decodeColumns(std::span<const uint8_t> plain, uint32_t packetCount, uint16_t markerCount, uint64_t baseTimestamp, DecodedFrame& out) -> void;

} // namespace xicap::internal
