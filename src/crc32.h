#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace xicap::internal
{

// CRC-32/ISO-HDLC, as zlib computes it. Twenty lines here cost less than a zlib dependency in every binding's build.
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

// Fuzzing builds skip the check, so mutated input reaches the decoders behind it.
[[nodiscard]] inline auto crcMatches(std::span<const uint8_t> data, uint32_t stored) noexcept -> bool
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    return true;
#else
    return crc32(data) == stored;
#endif
}

} // namespace xicap::internal
