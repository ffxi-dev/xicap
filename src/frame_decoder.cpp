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

auto FrameDecoder::decode(const format::FrameHeader& header, std::span<const uint8_t> payload, Frame& out) -> void
{
    if (header.plainSize == 0 || header.plainSize > format::MAX_PLAIN_SIZE)
    {
        badFrame(std::format("plain size {}", header.plainSize));
    }

    if (header.packetCount == 0 || header.packetCount > format::MAX_PACKETS)
    {
        badFrame(std::format("packet count {}", header.packetCount));
    }

    if (header.baseTimestamp < lastTimestamp_)
    {
        badFrame("it starts before the frame before it ends");
    }

    // One byte more than expected, to catch a payload that decodes to more.
    plain_.resize(size_t{ header.plainSize } + 1);
    auto in  = ZSTD_inBuffer{ payload.data(), payload.size(), 0 };
    auto buf = ZSTD_outBuffer{ plain_.data(), plain_.size(), 0 };
    while (buf.pos < buf.size)
    {
        const auto inBefore  = in.pos;
        const auto outBefore = buf.pos;
        const auto rc        = ZSTD_decompressStream(dctx_.get(), &buf, &in);
        if (ZSTD_isError(rc))
        {
            badFrame(std::format("zstd: {}", ZSTD_getErrorName(rc)));
        }

        if (in.pos == inBefore && buf.pos == outBefore)
        {
            break;
        }
    }

    if (in.pos != in.size || buf.pos != header.plainSize)
    {
        badFrame("its payload does not decode to its plain size");
    }

    decodeColumns(std::span{ plain_ }.first(header.plainSize), header.packetCount, header.markerCount, header.baseTimestamp, out);
    lastTimestamp_ = out.packets.back().timestamp;
}

} // namespace xicap::internal
