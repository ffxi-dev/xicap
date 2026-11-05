#pragma once

#include "xicap/types.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

// A frame's plaintext: its packets in columns. See FORMAT.md, Frames.
namespace xicap::frame
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
[[nodiscard]] auto encode(const Frame& frame) -> std::vector<uint8_t>;

[[noreturn]] auto bad(std::string_view why) -> void;

// Throws Error for a bad plaintext.
auto decode(std::span<const uint8_t> plain, uint32_t packetCount, uint32_t markerCount, uint64_t baseTimestamp, Frame& out) -> void;

[[nodiscard]] inline auto isGame(const uint8_t channel) noexcept -> bool
{
    return channel == static_cast<uint8_t>(Channel::Game);
}

// Each packet's group, numbered in order of the groups' first packets; returns how many groups there are.
auto assignGroups(std::span<const FramePacket> packets, std::vector<uint32_t>& group) -> uint32_t;

} // namespace xicap::frame
