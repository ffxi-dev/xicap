#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

// Unsigned LEB128 varints and 16-bit zigzag, as FORMAT.md's Conventions define them.
namespace xicap::internal
{

inline auto putVarint(std::vector<uint8_t>& out, uint64_t value) -> void
{
    while (value >= 0x80)
    {
        out.push_back(static_cast<uint8_t>(value | 0x80));
        value >>= 7;
    }

    out.push_back(static_cast<uint8_t>(value));
}

// Reads a varint for a field `bits` wide (8, 16, or 32). False when it runs past the end, takes more than
// ceil(bits / 7) bytes, or holds a value too large for the field.
[[nodiscard]] inline auto getVarint(std::span<const uint8_t> in, size_t& pos, unsigned bits, uint32_t& out) noexcept -> bool
{
    uint64_t value = 0;
    for (unsigned shift = 0; shift < bits && pos < in.size(); shift += 7)
    {
        const auto b = in[pos++];
        value |= uint64_t{ b & 0x7FU } << shift;
        if ((b & 0x80U) == 0)
        {
            out = static_cast<uint32_t>(value);
            return value >> bits == 0;
        }
    }

    return false;
}

[[nodiscard]] constexpr auto zigzag16(uint16_t delta) noexcept -> uint16_t
{
    return static_cast<uint16_t>((delta << 1) ^ static_cast<uint16_t>(static_cast<int16_t>(delta) >> 15));
}

[[nodiscard]] constexpr auto unzigzag16(uint16_t z) noexcept -> uint16_t
{
    return static_cast<uint16_t>((z >> 1) ^ static_cast<uint16_t>(-(z & 1)));
}

} // namespace xicap::internal
