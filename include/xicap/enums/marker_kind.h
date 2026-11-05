#pragma once

#include <cstdint>

namespace xicap
{

// Readers pass on kinds this enum does not name unchanged.
enum class MarkerKind : uint8_t
{
    Note   = 0,
    Login  = 1,
    Logout = 2,
};

} // namespace xicap
