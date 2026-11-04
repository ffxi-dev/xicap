#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>
#include <string_view>

// Text fields: UTF-8, padded with zero bytes, always ending with one.
namespace xicap::internal
{

template <size_t N>
auto toField(std::string_view text) -> std::array<char, N>
{
    // Cut between characters, never inside one.
    auto n = std::min(text.size(), N - 1);
    while (n < text.size() && n > 0 && (static_cast<unsigned char>(text[n]) & 0xC0U) == 0x80U)
    {
        --n;
    }
    std::array<char, N> field{};
    std::ranges::copy(text.substr(0, n), field.begin());
    return field;
}

template <size_t N>
auto fromField(const std::array<char, N>& field) -> std::string
{
    return { field.begin(), std::ranges::find(field, '\0') };
}

} // namespace xicap::internal
