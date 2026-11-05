#pragma once

#include <cstdint>

namespace xicap
{

enum class ExclusionAction : uint8_t
{
    Stub      = 1,
    ZeroRange = 2,
};

} // namespace xicap
