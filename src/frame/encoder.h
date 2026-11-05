#pragma once

#include "xicap/writer.h"

#include <cstdint>
#include <memory>
#include <span>
#include <vector>
#include <zstd.h>

namespace xicap::frame
{

// Compresses frames in file order into one zstd stream.
class Encoder
{
public:
    explicit Encoder(const FramePolicy& policy);

    // Flushed, so the payload decodes as soon as it is on disk.
    [[nodiscard]] auto compress(std::span<const uint8_t> plain) -> std::vector<uint8_t>;

private:
    std::unique_ptr<ZSTD_CCtx, decltype(&ZSTD_freeCCtx)> cctx_;
};

} // namespace xicap::frame
