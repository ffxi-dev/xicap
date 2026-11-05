#pragma once

#include "writer.h"

#include <filesystem>

namespace xicap
{

// Rewrites src at dst with other frames and compression, keeping its metadata, packets, and markers, then reads dst
// back and compares it with src. Any difference throws Error; on failure there is no file at dst.
auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, FramePolicy policy = FramePolicy::archive()) -> void;

} // namespace xicap
