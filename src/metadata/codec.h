#pragma once

#include "format/layout.h"
#include "xicap/metadata.h"

#include <cstdint>
#include <span>
#include <vector>

// The header and blocks: the capture's Metadata on disk.
namespace xicap::metadata
{

[[nodiscard]] auto encode(const Metadata& metadata) -> std::vector<uint8_t>;

// From the first sizeof(format::Header) bytes; returns how many blocks follow. Throws Error for a header that must be
// refused.
auto               readHeader(std::span<const uint8_t> bytes, Metadata& out) -> uint8_t;
[[nodiscard]] auto blockSize(std::span<const uint8_t> first) -> uint64_t;
auto               readBlock(std::span<const uint8_t> block, Metadata& out) -> uint32_t;

} // namespace xicap::metadata
