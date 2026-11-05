#pragma once

#include "types.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace xicap
{

struct Metadata
{
    CaptureId             captureId{}; // all zero: a writer picks a random one
    CaptureId             previousCaptureId{};
    uint64_t              startTimestamp{}; // a writer takes it from the first packet
    Origin                origin{ Origin::Live };
    ServerKind            serverKind{ ServerKind::Unknown };
    std::string           captureAgent;
    std::string           clientVersion;
    Character             character;
    std::optional<Source> source;
    std::vector<Block>    blocks;        // blocks of other types, in file order
    size_t                sourceIndex{}; // how many of blocks come before the source block

    auto operator==(const Metadata&) const -> bool = default;
};

inline constexpr size_t HEADER_SIZE = 160;

// Throws Error unless bytes start with a header this library reads.
auto checkHeader(std::span<const uint8_t> bytes) -> void;

} // namespace xicap
