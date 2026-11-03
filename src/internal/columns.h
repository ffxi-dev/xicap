#pragma once

#include "xicap/types.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// A format-4 packet frame's plaintext: packets in columns. See FORMAT.md, Packet frames.
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

// Timestamps must not go backwards; deltas must fit 32 bits; markers must be in packet order.
[[nodiscard]] auto encodeColumns(std::span<const Record> packets, std::span<const MarkerRecord> markers) -> std::vector<uint8_t>;

// A decoded packet frame, from either format: packets point into bytes.
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
};

// Throws Error(CorruptFrame) for a bad plaintext and Error(UnknownPacketFlag) for a must-understand flag.
auto decodeColumns(std::span<const uint8_t> plain, uint32_t packetCount, uint16_t markerCount, uint64_t baseTimestamp, DecodedFrame& out) -> void;

} // namespace xicap::internal
