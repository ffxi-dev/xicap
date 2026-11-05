#include "frame/encoder.h"
#include "format/layout.h"

#include <algorithm>
#include <format>

namespace xicap::frame
{

Encoder::Encoder(const FramePolicy& policy)
: cctx_(ZSTD_createCCtx())
{
    if (!cctx_)
    {
        throw Error("xicap: cannot create a zstd compressor");
    }

    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_compressionLevel, policy.compressionLevel);
    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_windowLog, std::clamp(policy.windowLog, 10, format::MAX_WINDOW_LOG));
    ZSTD_CCtx_setParameter(cctx_.get(), ZSTD_c_hashLog, policy.hashLog);
}

auto Encoder::compress(const std::span<const uint8_t> plain) -> std::vector<uint8_t>
{
    std::vector<uint8_t> payload(ZSTD_compressBound(plain.size()));
    auto                 in  = ZSTD_inBuffer{ plain.data(), plain.size(), 0 };
    auto                 out = ZSTD_outBuffer{ payload.data(), payload.size(), 0 };
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

    payload.resize(out.pos);
    return payload;
}

} // namespace xicap::frame
