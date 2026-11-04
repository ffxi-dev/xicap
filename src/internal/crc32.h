#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <span>

namespace xicap::internal
{

inline constexpr auto CRC32_TABLE = []
{
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i)
    {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k)
        {
            c = (c >> 1) ^ ((c & 1U) * 0xEDB88320U);
        }
        table[i] = c;
    }
    return table;
}();

[[nodiscard]] inline auto crc32(std::span<const uint8_t> data) noexcept -> uint32_t
{
    uint32_t state = 0xFFFFFFFFU;
    for (const auto b : data)
    {
        state = CRC32_TABLE[(state ^ b) & 0xFFU] ^ (state >> 8);
    }
    return state ^ 0xFFFFFFFFU;
}

// Whether the last 4 bytes are the CRC-32 of the rest.
[[nodiscard]] inline auto endsWithCrc(std::span<const uint8_t> bytes) noexcept -> bool
{
    uint32_t stored = 0;
    std::memcpy(&stored, bytes.data() + bytes.size() - sizeof(stored), sizeof(stored));
    return crc32(bytes.first(bytes.size() - sizeof(stored))) == stored;
}

} // namespace xicap::internal
