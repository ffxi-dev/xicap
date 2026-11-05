#pragma once

#include "writer.h"

#include <cstdint>
#include <filesystem>

namespace xicap
{

// Rewrites src at dst with other frames and compression, keeping its metadata, packets, and markers, then reads dst
// back and compares it with src. dst changes only once the copy matches; any difference throws Error.
auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, FramePolicy policy = FramePolicy::archive()) -> void;

// Writes the packets of source from the first frame that does not end within its first fromByte bytes, as a new
// capture at out that continues source: a new id, with source's id as previousCaptureId. For a recording whose upload
// was cut off at fromByte. Returns the packets written; with none, it writes no file.
auto continueFrom(const std::filesystem::path& source, uint64_t fromByte, const std::filesystem::path& out, FramePolicy policy = FramePolicy::live()) -> uint64_t;

} // namespace xicap
