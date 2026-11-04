#pragma once

#include "columns.h"
#include "format.h"

#include <cstdint>
#include <memory>
#include <span>
#include <vector>
#include <zstd.h>

namespace xicap::internal
{

// Decodes frames in file order: their payloads are one zstd stream.
class FrameDecoder
{
public:
    FrameDecoder();

    // Throws Error for a bad frame. Its CRC is already checked.
    auto decode(const format::FrameHeader& header, std::span<const uint8_t> payload, Frame& out) -> void;

private:
    struct Free
    {
        auto operator()(ZSTD_DCtx* c) const noexcept -> void
        {
            ZSTD_freeDCtx(c);
        }
    };

    std::unique_ptr<ZSTD_DCtx, Free> dctx_;
    std::vector<uint8_t>             plain_;
    uint64_t                         lastTimestamp_{};
};

} // namespace xicap::internal
