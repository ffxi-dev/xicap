#pragma once

#include <cstdint>

namespace xicap
{

enum class PacketDirection : uint8_t
{
    ServerToClient = 0,
    ClientToServer = 1,
};

} // namespace xicap
