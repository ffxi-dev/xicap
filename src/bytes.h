#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

static_assert(std::endian::native == std::endian::little, "the format's structs are read and written as they lie in memory");

namespace xicap::internal
{

// The T at bytes[at]. The caller checks that it fits.
template <typename T, typename Byte, size_t N>
    requires(sizeof(Byte) == 1)
[[nodiscard]] auto load(std::span<Byte, N> bytes, size_t at = 0) noexcept -> T
{
    std::array<std::byte, sizeof(T)> raw{};
    std::ranges::copy(std::as_bytes(bytes).subspan(at, sizeof(T)), raw.begin());
    return std::bit_cast<T>(raw);
}

template <typename T>
auto append(std::vector<uint8_t>& out, const T& value) -> void
{
    const auto raw = std::bit_cast<std::array<uint8_t, sizeof(T)>>(value);
    out.insert(out.end(), raw.begin(), raw.end());
}

} // namespace xicap::internal
