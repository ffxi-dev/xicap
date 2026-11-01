#pragma once

#include <array>
#include <cstdint>
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
            c = (c & 1U) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
        }
        table[i] = c;
    }
    return table;
}();

class Crc32
{
public:
    auto update(std::span<const uint8_t> data) noexcept -> void
    {
        for (const auto b : data)
        {
            state_ = CRC32_TABLE[(state_ ^ b) & 0xFFU] ^ (state_ >> 8);
        }
    }

    [[nodiscard]] auto value() const noexcept -> uint32_t
    {
        return state_ ^ 0xFFFFFFFFU;
    }

private:
    uint32_t state_ = 0xFFFFFFFFU;
};

[[nodiscard]] inline auto crc32(std::span<const uint8_t> data) noexcept -> uint32_t
{
    Crc32 crc;
    crc.update(data);
    return crc.value();
}

} // namespace xicap::internal
