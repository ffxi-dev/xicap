#pragma once

#include <cstdint>
#include <span>

namespace xicap
{

// The zstd dictionary this build was compiled with. Used by default when
// writing; captures embed whatever dictionary they were written with, so a
// reader never depends on a matching build.
[[nodiscard]] auto builtinDictionary() -> std::span<const uint8_t>;

} // namespace xicap
