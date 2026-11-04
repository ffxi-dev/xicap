#include "frame_decoder.h"

#include <format>

namespace xicap::internal
{

FrameDecoder::FrameDecoder()
: dctx_(ZSTD_createDCtx())
{
    if (!dctx_)
    {
        throw Error("xicap: cannot create a zstd decoder");
    }
    ZSTD_DCtx_setParameter(dctx_.get(), ZSTD_d_windowLogMax, format::MAX_WINDOW_LOG);
}

auto FrameDecoder::decode(const format::FrameHeader& header, std::span<const uint8_t> payload, DecodedFrame& out) -> void
{
    if (header.plainSize == 0 || header.plainSize > format::MAX_PLAIN_SIZE)
    {
        throw Error(std::format("xicap: bad frame: plain size {}", header.plainSize));
    }
    if (header.packetCount == 0 || header.packetCount > format::MAX_PACKETS)
    {
        throw Error(std::format("xicap: bad frame: packet count {}", header.packetCount));
    }
    if (header.baseTimestamp < lastTimestamp_)
    {
        throw Error("xicap: bad frame: it starts before the frame before it ends");
    }
    // One byte more than expected, to catch a payload that decodes to more.
    plain_.resize(size_t{ header.plainSize } + 1);
    auto in  = ZSTD_inBuffer{ payload.data(), payload.size(), 0 };
    auto buf = ZSTD_outBuffer{ plain_.data(), plain_.size(), 0 };
    // Until the output is full or a call makes no progress.
    while (buf.pos < buf.size)
    {
        const auto inBefore  = in.pos;
        const auto outBefore = buf.pos;
        const auto rc        = ZSTD_decompressStream(dctx_.get(), &buf, &in);
        if (ZSTD_isError(rc))
        {
            throw Error(std::format("xicap: bad frame: zstd: {}", ZSTD_getErrorName(rc)));
        }
        if (in.pos == inBefore && buf.pos == outBefore)
        {
            break;
        }
    }
    if (in.pos != in.size || buf.pos != header.plainSize)
    {
        throw Error("xicap: bad frame: its payload does not decode to its plain size");
    }
    decodeColumns(std::span{ plain_ }.first(header.plainSize), header.packetCount, header.markerCount, header.baseTimestamp, out);
    lastTimestamp_ = out.packets.back().timestamp;
}

} // namespace xicap::internal
