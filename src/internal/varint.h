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

[[nodiscard]] constexpr auto varintSize(uint64_t value) noexcept -> size_t
{
    size_t n = 1;
    while (value >= 0x80)
    {
        value >>= 7;
        n++;
    }
    return n;
}

// Reads a varint filling a field `bits` wide (8, 16, or 32). False when it runs past the end, takes more than
// ceil(bits / 7) bytes or more bytes than its value needs, or holds a value too large for the field.
[[nodiscard]] inline auto getVarint(std::span<const uint8_t> in, size_t& pos, unsigned bits, uint32_t& out) noexcept -> bool
{
    const unsigned maxBytes = (bits + 6) / 7;
    uint64_t       value    = 0;
    for (unsigned i = 0; i < maxBytes; ++i)
    {
        if (pos >= in.size())
        {
            return false;
        }
        const uint8_t b = in[pos++];
        value |= uint64_t{ b & 0x7FU } << (7 * i);
        if ((b & 0x80U) == 0)
        {
            if (value >> bits != 0 || (i > 0 && b == 0))
            {
                return false;
            }
            out = static_cast<uint32_t>(value);
            return true;
        }
    }
    return false;
}

[[nodiscard]] constexpr auto zigzag16(int16_t n) noexcept -> uint16_t
{
    return static_cast<uint16_t>((static_cast<uint16_t>(n) << 1) ^ static_cast<uint16_t>(n >> 15));
}

[[nodiscard]] constexpr auto unzigzag16(uint16_t z) noexcept -> int16_t
{
    return static_cast<int16_t>((z >> 1) ^ static_cast<uint16_t>(-(z & 1)));
}

} // namespace xicap::internal
