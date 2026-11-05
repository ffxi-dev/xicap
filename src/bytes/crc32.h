#pragma once

#include "bytes/bytes.h"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace xicap::bytes
{

// CRC-32/ISO-HDLC, as zlib computes it.
inline constexpr auto CRC32_TABLE = []
{
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i)
    {
        auto c = i;
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
    auto state = uint32_t{ 0xFFFFFFFF };
    for (const auto b : data)
    {
        state = CRC32_TABLE[(state ^ b) & 0xFFU] ^ (state >> 8);
    }

    return state ^ 0xFFFFFFFFU;
}

// Appends the CRC of out from byte `from` on.
inline auto appendCrc(std::vector<uint8_t>& out, size_t from = 0) -> void
{
    append(out, crc32(std::span{ out }.subspan(from)));
}

// The last 4 bytes are the CRC of the rest. Fuzzing builds skip the check, so mutated input reaches the decoders behind
// it.
[[nodiscard]] inline auto endsWithCrc(std::span<const uint8_t> bytes) noexcept -> bool
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    return true;
#else
    const auto n = bytes.size() - sizeof(uint32_t);
    return crc32(bytes.first(n)) == load<uint32_t>(bytes, n);
#endif
}

} // namespace xicap::bytes
