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
// Throws Error for metadata whose blocks do not fit the format.
auto check(const Metadata& metadata) -> void;

// From the first sizeof(format::Header) bytes; returns how many blocks follow. Throws Error for a header that must be
// refused.
auto readHeader(std::span<const uint8_t> bytes, Metadata& out) -> uint8_t;
// The whole block's size, from its first 8 bytes. Throws Error for a block over 16 MiB.
[[nodiscard]] auto blockSize(std::span<const uint8_t> first) -> uint64_t;
// Throws Error for a bad CRC, a second source block, or a short source block.
auto readBlock(std::span<const uint8_t> block, Metadata& out) -> void;

} // namespace xicap::metadata
