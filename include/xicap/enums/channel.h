#pragma once

#include <cstdint>

namespace xicap
{

// Readers pass on packets of channels this enum does not name.
enum class Channel : uint8_t
{
    Game   = 0,
    Search = 1,
};

} // namespace xicap
