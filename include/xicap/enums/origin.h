#pragma once

#include <cstdint>

namespace xicap
{

enum class Origin : uint8_t
{
    Unknown   = 0,
    Live      = 1,
    Converted = 2,
};

} // namespace xicap
