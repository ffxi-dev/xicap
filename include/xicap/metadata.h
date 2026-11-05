#pragma once

#include "types.h"

#include <cstdint>
#include <optional>
#include <string>

namespace xicap
{

// What a capture's header and blocks say about it.
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

    auto operator==(const Metadata&) const -> bool = default;
};

} // namespace xicap
