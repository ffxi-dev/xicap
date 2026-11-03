#include "internal/transcode.h"
#include "internal/access.h"
#include "internal/chain.h"
#include "internal/crc32.h"

#include "xicap/reader.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <format>
#include <optional>

namespace xicap
{
namespace internal
{
namespace
{

[[noreturn]] auto refuse(const std::string& why) -> void
{
    throw Error(ErrorCode::TranscodeRefused, "xicap: transcode refused: " + why);
}

[[noreturn]] auto mismatch(const std::string& why) -> void
{
    throw Error(ErrorCode::TranscodeMismatch, "xicap: transcode check failed: " + why);
}

template <typename T>
auto hexOf(const T& bytes) -> std::string
{
    std::string out;
    for (const auto b : bytes)
    {
        out += std::format("{:02x}", static_cast<unsigned>(b));
    }
    return out;
}

auto blockType(const std::vector<uint8_t>& block) -> uint32_t
{
    uint32_t type = 0;
    std::memcpy(&type, block.data(), sizeof(type));
    return type;
}

// Resign: the header names the new key and format 4; the blocks lose the dictionary and gain a SOURCE block naming
// src, unless src has one.
auto resignStart(Reader& src, const Verification& v, const TranscodeOptions& options, std::vector<uint8_t>& header, std::vector<std::vector<uint8_t>>& blocks) -> void
{
    std::erase_if(blocks, [](const std::vector<uint8_t>& block)
                  {
                      return blockType(block) == EXT_ZSTD_DICT;
                  });
    if (!std::ranges::any_of(blocks, [](const std::vector<uint8_t>& block)
                             {
                                 return blockType(block) == EXT_SOURCE;
                             }))
    {
        const auto& trailer = Access::trailer(src);
        std::string lines   = std::format("signing-key {}\nsigned-to-end {}\nverified-packets {}\nfooter-signature {}\ntranscoded-by {}\n",
                                          hexOf(src.signingKey()),
                                          v.signedToEnd ? "yes" : "no",
                                          v.verifiedPackets,
                                          src.complete() ? hexOf(trailer.signature) : "none",
                                          options.agent);
        SourceInfo  source{ .format = "xicap", .formatVersion = std::format("{}.{}", src.versionMajor(), src.versionMinor()), .skippedRecords = 0, .utcOffsetSeconds = 0, .sourceHash = options.sourceHash, .metadata = { lines.begin(), lines.end() } };
        source.metadata.insert(source.metadata.end(), options.metadata.begin(), options.metadata.end());
        blocks.push_back(encodeBlock(EXT_SOURCE, encodeSource(source)));
    }

    const SigningKey key(options.seed);
    const auto       count                 = static_cast<uint32_t>(blocks.size());
    header[offsetof(Header, versionMajor)] = VERSION_MAJOR;
    header[offsetof(Header, versionMinor)] = VERSION_MINOR;
    std::memcpy(header.data() + offsetof(Header, extensionCount), &count, sizeof(count));
    std::memset(header.data() + offsetof(Header, dictionaryId), 0, sizeof(uint32_t));
    std::memcpy(header.data() + offsetof(Header, signingKey), key.publicKey().data(), key.publicKey().size());
    const auto crc = crc32({ header.data(), header.size() - sizeof(uint32_t) });
    std::memcpy(header.data() + header.size() - sizeof(crc), &crc, sizeof(crc));
}

// Reads src and dst side by side; any difference is a mismatch.
auto compare(const std::filesystem::path& src, const std::filesystem::path& dst) -> void
{
    Reader     a(src), b(dst);
    ReadPacket pa{}, pb{};
    for (uint64_t i = 0;; ++i)
    {
        const bool na = a.next(pa);
        const bool nb = b.next(pb);
        if (na != nb)
        {
            mismatch(std::format("packet {} is in only one of the files", i));
        }
        if (!na)
        {
            return;
        }
        const bool same = pa.timestamp == pb.timestamp && pa.channel == pb.channel && pa.flags == pb.flags && pa.opcode == pb.opcode &&
                          std::ranges::equal(pa.data, pb.data) && pa.markers.size() == pb.markers.size() &&
                          std::ranges::equal(pa.markers, pb.markers, [](const ReadMarker& x, const ReadMarker& y)
                                             {
                                                 return x.kind == y.kind && x.text == y.text;
                                             });
        if (!same)
        {
            mismatch(std::format("packet {} differs", i));
        }
    }
}

} // namespace

auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, const TranscodeOptions& options, const TranscodeHooks& hooks) -> TranscodeResult
{
    Reader     in(src);
    const auto v    = in.verify();
    const bool seal = options.signing == Signing::Seal;
    if (seal && in.versionMajor() == 3)
    {
        refuse("a seal keeps the signer's signatures, which format 3 signs over compressed bytes; resign it");
    }
    if (seal && in.complete() && !v.signedToEnd)
    {
        refuse("a complete file not signed to the end");
    }

    auto header = Access::headerBytes(in);
    auto blocks = Access::blockBytes(in);
    if (!seal)
    {
        resignStart(in, v, options, header, blocks);
    }
    // A cut-off file keeps the last checkpoint that verifies.
    std::optional<CheckpointPayload> carried;
    if (seal && !in.complete() && v.verifiedPackets > 0)
    {
        carried = CheckpointPayload{ .packets = v.verifiedPackets, .digest = v.checkpointDigest, .signature = v.checkpointSignature };
    }

    const auto      tmp = std::filesystem::path(dst).concat(".tmp");
    TranscodeResult result{ .packets = 0, .markers = 0, .bytesIn = std::filesystem::file_size(src), .bytesOut = 0 };
    try
    {
        {
            const auto writer = Access::rewriter(tmp, options.policy, std::move(header), std::move(blocks), seal ? nullptr : &options.seed);
            if (seal)
            {
                if (in.complete())
                {
                    Access::copyFooter(*writer, Access::trailer(in).signature);
                }
                else
                {
                    Access::endUnsigned(*writer);
                }
                const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                Access::seal(*writer, options.seed, options.agent, hooks.sealedAt != 0 ? hooks.sealedAt : static_cast<uint64_t>(now));
            }
            ReadPacket   p{};
            CopiedPacket copy;
            while (in.next(p))
            {
                if (hooks.edit)
                {
                    const auto* d = reinterpret_cast<const uint8_t*>(p.data.data());
                    copy          = { p.timestamp, p.flags, p.channel, p.opcode, { d, d + p.data.size() }, { p.markers.begin(), p.markers.end() } };
                    hooks.edit(result.packets, copy);
                    p = { .timestamp = copy.timestamp, .channel = copy.channel, .opcode = copy.opcode, .flags = copy.flags, .direction = p.direction, .data = std::as_bytes(std::span{ copy.data }), .markers = copy.markers };
                }
                result.markers += p.markers.size();
                Access::add(*writer, p);
                result.packets++;
                if (carried && result.packets == carried->packets)
                {
                    Access::carry(*writer, *carried);
                }
            }
            writer->close();
        }
        if (hooks.check)
        {
            compare(src, tmp);
            Reader     out(tmp);
            const auto w    = out.verify();
            const bool good = out.complete() && !w.firstFailureOffset &&
                              (seal ? (in.complete() ? w.signedToEnd : w.verifiedPackets == (carried ? carried->packets : 0)) && w.seal && w.seal->good
                                    : w.signedToEnd);
            if (!good)
            {
                mismatch("its signatures do not verify as expected");
            }
        }
        result.bytesOut = std::filesystem::file_size(tmp);
        std::filesystem::rename(tmp, dst);
    }
    catch (...)
    {
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        throw;
    }
    return result;
}

} // namespace internal

auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, const TranscodeOptions& options) -> TranscodeResult
{
    return internal::transcode(src, dst, options, {});
}

} // namespace xicap
