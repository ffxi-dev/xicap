#pragma once

#include "writer.h"

#include <filesystem>

namespace xicap
{

// Rewrites src at dst with other frames and compression, keeping its metadata, packets, and markers, then reads dst
// back and compares it with src. Any difference throws Error. src and dst must be different files; an existing dst is
// overwritten, and removed if the rewrite then fails. With Chat::Redact, each game packet's chat text is zeroed and
// flagged as a writer that does not keep chat would, and dst is compared with src redacted the same way.
auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, FramePolicy policy = FramePolicy::archive(), Chat chat = Chat::Keep) -> void;

} // namespace xicap
