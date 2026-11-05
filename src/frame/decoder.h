#pragma once

#include "format/layout.h"
#include "frame/frame.h"

#include <cstdint>
#include <memory>
#include <span>
#include <vector>
#include <zstd.h>

namespace xicap::frame
{

// Decodes frames in file order: their payloads are one zstd stream.
class Decoder
{
public:
    Decoder();

    // Throws Error for a bad frame. Its CRC is already checked.
    auto decode(const format::FrameHeader& header, std::span<const uint8_t> payload, Frame& out) -> void;
    // The last packet's timestamp, or 0 before the first frame.
    [[nodiscard]] auto lastTimestamp() const noexcept -> uint64_t
    {
        return lastTimestamp_;
    }

private:
    std::unique_ptr<ZSTD_DCtx, decltype(&ZSTD_freeDCtx)> dctx_;
    std::vector<uint8_t>                                 plain_;
    uint64_t                                             lastTimestamp_{};
};

} // namespace xicap::frame
