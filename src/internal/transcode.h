#pragma once

#include "xicap/transcode.h"

#include <functional>
#include <vector>

namespace xicap::internal
{

// A packet as transcode copies it; tests change one to show what the check and the signatures catch.
struct CopiedPacket
{
    uint64_t                timestamp{};
    uint16_t                flags{};
    uint8_t                 channel{};
    uint16_t                opcode{};
    std::vector<uint8_t>    data;
    std::vector<ReadMarker> markers;
};

struct TranscodeHooks
{
    // Called on each packet, by index, before it is written.
    std::function<void(uint64_t, CopiedPacket&)> edit;
    // Read dst back and compare. Off only in tests that craft a bad file.
    bool check = true;
    // The seal's time, Unix ms; 0 for now. Set for files that must come out the same each time.
    uint64_t sealedAt = 0;
};

auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, const TranscodeOptions& options, const TranscodeHooks& hooks) -> TranscodeResult;

} // namespace xicap::internal
