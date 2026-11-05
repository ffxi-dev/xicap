#pragma once

#include "enums/exclusion_action.h"
#include "enums/exclusion_direction.h"
#include "types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace xicap
{

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

// The packet as a writer with this policy stores it. The policy must be one a writer accepts. Throws Error for a game
// packet under 4 bytes.
[[nodiscard]] auto applyPolicy(const ExclusionPolicy& policy, const OutPacket& packet) -> StoredPacket;

} // namespace xicap
