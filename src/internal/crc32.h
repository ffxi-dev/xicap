#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace xicap::internal
{

inline auto crc32Table() -> const std::array<uint32_t, 256>&
{
    static const auto tbl = []
    {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; ++i)
        {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
            {
                c = (c & 1U) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
            }
            t[i] = c;
        }
        return t;
    }();
    return tbl;
}

class Crc32
{
public:
    auto update(std::span<const uint8_t> data) noexcept -> void
    {
        const auto& tbl = crc32Table();
        for (auto b : data)
        {
            state_ = tbl[(state_ ^ b) & 0xFFU] ^ (state_ >> 8);
        }
    }

    [[nodiscard]] auto value() const noexcept -> uint32_t
    {
        return state_ ^ 0xFFFFFFFFU;
    }

private:
    uint32_t state_ = 0xFFFFFFFFU;
};

} // namespace xicap::internal
