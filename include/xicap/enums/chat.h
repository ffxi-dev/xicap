#pragma once

#include <cstdint>

namespace xicap
{

// Whether a writer zeroes the text players write to each other. See FORMAT.md, Redaction.
enum class Chat : uint8_t
{
    Redact = 0,
    Keep   = 1,
};

} // namespace xicap
