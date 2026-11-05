#pragma once

#include <cstdint>

namespace xicap
{

enum class ServerKind : uint8_t
{
    Unknown = 0,
    Retail  = 1,
    Private = 2,
};

} // namespace xicap
