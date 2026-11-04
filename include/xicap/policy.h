#pragma once

#include "types.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace xicap
{

enum class ExclusionDirection : uint8_t
{
    ServerToClient = 0,
    ClientToServer = 1,
    Both           = 2,
};

enum class ExclusionAction : uint8_t
{
    Stub      = 1,
    ZeroRange = 2,
};

inline constexpr uint32_t TO_END = 0xFFFFFFFF;

struct ByteRange
{
    uint32_t offset{};
    uint32_t length{}; // TO_END runs to the packet's end

    auto operator==(const ByteRange&) const -> bool = default;
};

struct ExclusionRule
{
    uint8_t                channel{};
    ExclusionDirection     direction{};
    ExclusionAction        action{};
    uint16_t               opcode{};
    std::vector<ByteRange> ranges;

    auto operator==(const ExclusionRule&) const -> bool = default;
};

// What a writer removes from packets before they reach disk. A policy with no rules keeps everything.
struct ExclusionPolicy
{
    std::string                name;
    uint32_t                   version{};
    std::vector<ExclusionRule> rules;

    auto operator==(const ExclusionPolicy&) const -> bool = default;
};

// xicap-default version 2: zeroes the text of chat, keeping each packet's layout. See FORMAT.md, Exclusion.
[[nodiscard]] auto defaultExclusionPolicy() -> const ExclusionPolicy&;

struct OutPacket
{
    uint64_t                   timestamp{};
    PacketDirection            direction{};
    std::span<const std::byte> data;
    uint8_t                    channel = static_cast<uint8_t>(Channel::Game);
    uint16_t                   opcode{};     // ignored on the game channel, where the packet's header holds it
    uint16_t                   provenance{}; // PacketFlag::Provenance bits
};

struct StoredPacket
{
    uint16_t               opcode{};
    uint16_t               flags{};
    std::vector<std::byte> data;
};

// The packet as a writer with this policy stores it. Throws Error for a game packet under 4 bytes or a policy a
// writer refuses.
[[nodiscard]] auto applyPolicy(const ExclusionPolicy& policy, const OutPacket& packet) -> StoredPacket;

} // namespace xicap
