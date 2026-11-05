#include "frame/encoder.h"
#include "format/layout.h"

#include <format>
#include <utility>

namespace xicap::frame
{

Encoder::Encoder(const FramePolicy& policy)
: cctx_(ZSTD_createCCtx(), ZSTD_freeCCtx)
{
    if (!cctx_)
    {
        throw Error("xicap: cannot create a zstd compressor");
    }

    for (const auto [parameter, value] : { std::pair{ ZSTD_c_compressionLevel, policy.compressionLevel },
                                           std::pair{ ZSTD_c_windowLog, policy.windowLog },
                                           std::pair{ ZSTD_c_hashLog, policy.hashLog } })
    {
        if (const auto rc = ZSTD_CCtx_setParameter(cctx_.get(), parameter, value); ZSTD_isError(rc))
        {
            throw Error(std::format("xicap: zstd: {}", ZSTD_getErrorName(rc)));
        }
    }
}

auto Encoder::encode(const Frame& frame) -> std::vector<uint8_t>
{
    const auto           plain = encodeColumns(frame);
    std::vector<uint8_t> payload(ZSTD_compressBound(plain.size()));
    auto                 in  = ZSTD_inBuffer{ .src = plain.data(), .size = plain.size(), .pos = 0 };
    auto                 out = ZSTD_outBuffer{ .dst = payload.data(), .size = payload.size(), .pos = 0 };
    while (true)
    {
        const auto rc = ZSTD_compressStream2(cctx_.get(), &out, &in, ZSTD_e_flush);
        if (ZSTD_isError(rc))
        {
            throw Error(std::format("xicap: zstd: {}", ZSTD_getErrorName(rc)));
        }

        if (rc == 0)
        {
            break;
        }

        payload.resize(payload.size() * 2);
        out.dst  = payload.data();
        out.size = payload.size();
    }

    std::vector<uint8_t> encoded;
    bytes::append(encoded, format::FrameHeader{
                               .magic         = format::FRAME_MAGIC,
                               .payloadSize   = static_cast<uint32_t>(out.pos),
                               .plainSize     = static_cast<uint32_t>(plain.size()),
                               .packetCount   = static_cast<uint32_t>(frame.packets.size()),
                               .markerCount   = static_cast<uint32_t>(frame.markers.size()),
                               .baseTimestamp = frame.packets.front().timestamp,
                           });
    encoded.insert(encoded.end(), payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(out.pos));
    return encoded;
}

} // namespace xicap::frame
