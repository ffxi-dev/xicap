#include "internal/transcode.h"
#include "internal/access.h"
#include "internal/chain.h"
#include "internal/crc32.h"

#include "xicap/reader.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <format>
#include <memory>
#include <optional>
#include <random>

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

auto blockType(const std::vector<uint8_t>& block) -> uint32_t
{
    uint32_t type = 0;
    std::memcpy(&type, block.data(), sizeof(type));
    return type;
}

// Reissue with a signer: the blocks lose any SOURCE_SIGNER and gain the given one after SOURCE; the header counts them.
auto restateSigner(const SourceSigner& signer, std::vector<uint8_t>& header, std::vector<std::vector<uint8_t>>& blocks) -> void
{
    std::erase_if(blocks, [](const std::vector<uint8_t>& block)
                  {
                      return blockType(block) == EXT_SOURCE_SIGNER;
                  });
    const auto source = std::ranges::find_if(blocks, [](const std::vector<uint8_t>& block)
                                             {
                                                 return blockType(block) == EXT_SOURCE;
                                             });
    if (source == blocks.end())
    {
        refuse("a source signer needs a SOURCE block");
    }
    blocks.insert(std::next(source), encodeBlock(EXT_SOURCE_SIGNER, encodeSourceSigner(signer)));
    const auto count = static_cast<uint32_t>(blocks.size());
    std::memcpy(header.data() + offsetof(Header, extensionCount), &count, sizeof(count));
    const auto crc = crc32({ header.data(), header.size() - sizeof(uint32_t) });
    std::memcpy(header.data() + header.size() - sizeof(crc), &crc, sizeof(crc));
}

// A file beside dst that no other call names, and that becomes dst only once whole: a failed call leaves dst as it
// was, and no call can write over its own src.
class Staged
{
public:
    explicit Staged(const std::filesystem::path& dst)
    : dst_(dst)
    {
        std::random_device rd;
        path_ = std::filesystem::path(dst).concat(std::format(".{:08x}{:08x}.tmp", rd(), rd()));
    }
    ~Staged()
    {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }
    Staged(const Staged&)                    = delete;
    auto operator=(const Staged&) -> Staged& = delete;

    [[nodiscard]] auto path() const -> const std::filesystem::path&
    {
        return path_;
    }
    auto publish() -> void
    {
        std::filesystem::rename(path_, dst_);
    }

private:
    std::filesystem::path dst_;
    std::filesystem::path path_;
};

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
    // A sealed file whose end was never signed stands for the cut-off recording it was made from.
    const bool cutOff = !in.complete() || (Access::trailer(in).trailerFlags & TrailerFlag::EndUnsigned) != 0;
    if (v.firstFailureOffset)
    {
        refuse(std::format("a signature fails at offset {}", *v.firstFailureOffset));
    }
    if (v.seal && !v.seal->good)
    {
        refuse("its seal fails");
    }
    if (in.complete() && !cutOff && !v.signedToEnd)
    {
        refuse("a complete file not signed to the end");
    }

    auto header = Access::headerBytes(in);
    auto blocks = Access::blockBytes(in);
    if (!seal)
    {
        if (!v.signedToEnd)
        {
            refuse("a reissue takes a file signed to the end");
        }
        if (SigningKey(options.seed).publicKey() != in.signingKey())
        {
            refuse("a reissue is signed by the file's own signer");
        }
        if (options.signer)
        {
            restateSigner(*options.signer, header, blocks);
        }
    }
    // A cut-off file keeps the last checkpoint that verifies.
    std::optional<CheckpointPayload> kept;
    if (seal && cutOff && v.verifiedPackets > 0)
    {
        kept = CheckpointPayload{ .packets = v.verifiedPackets, .digest = v.checkpointDigest, .signature = v.checkpointSignature };
    }

    Staged          tmp(dst);
    TranscodeResult result{ .packets = 0, .markers = 0, .bytesIn = std::filesystem::file_size(src), .bytesOut = 0 };
    {
        const auto writer = Access::rewriter(tmp.path(), options.policy, std::move(header), std::move(blocks), seal ? nullptr : &options.seed);
        if (seal)
        {
            if (cutOff)
            {
                Access::endUnsigned(*writer);
            }
            else
            {
                Access::copyFooter(*writer, Access::trailer(in).signature);
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
            if (kept && result.packets == kept->packets)
            {
                Access::keep(*writer, *kept);
            }
        }
        writer->close();
    }
    if (hooks.check)
    {
        compare(src, tmp.path());
        Reader     out(tmp.path());
        const auto w    = out.verify();
        const bool good = out.complete() && !w.firstFailureOffset &&
                          (seal ? (cutOff ? w.verifiedPackets == (kept ? kept->packets : 0) : w.signedToEnd) && w.seal && w.seal->good
                                : w.signedToEnd);
        if (!good)
        {
            mismatch("its signatures do not verify as expected");
        }
    }
    result.bytesOut = std::filesystem::file_size(tmp.path());
    tmp.publish();
    return result;
}

} // namespace internal

auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, const TranscodeOptions& options) -> TranscodeResult
{
    return internal::transcode(src, dst, options, {});
}

auto continueFrom(const std::filesystem::path& source, uint64_t fromByte, const std::filesystem::path& out, const SecretSeed& seed, FramePolicy policy) -> uint64_t
{
    using internal::Access;
    Reader       in(source);
    WriterConfig config{};
    config.captureAgent      = in.captureAgent();
    config.clientVersion     = in.clientVersion();
    config.character         = in.character();
    config.clockSource       = in.clockSource();
    config.origin            = in.origin();
    config.network           = in.network();
    config.startContext      = StartContext::MidSession;
    config.previousCaptureId = in.captureId();
    config.signingSeed       = seed;
    config.policy            = in.policy();
    config.source            = in.source();

    std::optional<internal::Staged> tmp;
    std::unique_ptr<Writer>         writer;
    uint64_t                        packets = 0;
    ReadPacket                      p{};
    while (in.next(p))
    {
        if (Access::frameEnd(in) <= fromByte)
        {
            continue;
        }
        if (!writer)
        {
            tmp.emplace(out);
            writer = std::make_unique<Writer>(tmp->path(), config, policy);
        }
        Access::add(*writer, p);
        packets++;
    }
    if (!writer)
    {
        return 0;
    }
    writer->close();
    writer.reset();
    tmp->publish();
    return packets;
}

} // namespace xicap
