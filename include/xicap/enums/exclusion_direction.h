#pragma once

#include <cstdint>

namespace xicap
{

enum class ExclusionDirection : uint8_t
{
    ServerToClient = 0,
    ClientToServer = 1,
    Both           = 2,
};

} // namespace xicap
