#pragma once

#include "internal/chain.h"
#include "xicap/reader.h"
#include "xicap/writer.h"

#include <memory>
#include <span>
#include <string>
#include <vector>

// What transcode, and tests, reach below the public API for: a reader's raw header and blocks, and a writer that
// rewrites a capture without applying a policy or signing it.
namespace xicap::internal
{

// A whole extension block, from type to crc. Defined in writer.cpp.
auto encodeBlock(uint32_t type, std::span<const uint8_t> payload) -> std::vector<uint8_t>;
auto encodeSource(const SourceInfo& source) -> std::vector<uint8_t>;
auto encodeSourceSigner(const SourceSigner& signer) -> std::vector<uint8_t>;

struct Access
{
    static auto headerBytes(const Reader& r) -> const std::vector<uint8_t>&
    {
        return r.headerBytes_;
    }
    static auto blockBytes(const Reader& r) -> const std::vector<std::vector<uint8_t>>&
    {
        return r.blockBytes_;
    }
    static auto trailer(const Reader& r) -> const FooterTrailer&
    {
        return r.trailer_;
    }
    // The file offset just past the packet frame the reader is in.
    static auto frameEnd(const Reader& r) -> uint64_t
    {
        return r.nextOffset_;
    }

    // Writes header and blocks unchanged. With a signer, signs the footer with it; without, the caller says what the
    // footer's signature is.
    static auto rewriter(const std::filesystem::path& path, const FramePolicy& policy, std::vector<uint8_t> header, std::vector<std::vector<uint8_t>> blocks, const SecretSeed* signer) -> std::unique_ptr<Writer>
    {
        return std::unique_ptr<Writer>(new Writer(path, policy, std::move(header), std::move(blocks), signer));
    }
    // The packet as stored, with the markers before it.
    static auto add(Writer& w, const ReadPacket& p) -> void
    {
        for (const auto& m : p.markers)
        {
            w.queueMarker(m.kind, m.text);
        }
        w.add(p.timestamp, p.flags, p.channel, p.opcode, { reinterpret_cast<const uint8_t*>(p.data.data()), p.data.size() });
    }
    // A marker as stored, unchanged.
    static auto marker(Writer& w, MarkerKind kind, std::string_view text) -> void
    {
        w.queueMarker(kind, text);
    }
    // Ends the frame and writes a checkpoint frame, unchanged; the seal covers it.
    static auto keep(Writer& w, const CheckpointPayload& checkpoint) -> void
    {
        w.endFrame(false);
        w.writeCheckpoint(checkpoint);
        w.keptCheckpoint_ = checkpoint;
    }
    static auto copyFooter(Writer& w, const Signature& signature) -> void
    {
        w.footerSignature_ = Writer::FooterSignature::Copy;
        w.copiedSignature_ = signature;
    }
    static auto endUnsigned(Writer& w) -> void
    {
        w.footerSignature_ = Writer::FooterSignature::Unsigned;
    }
    static auto seal(Writer& w, const SecretSeed& seed, std::string agent, uint64_t sealedAt) -> void
    {
        w.sealKey_   = std::make_unique<SigningKey>(seed);
        w.sealAgent_ = std::move(agent);
        w.sealedAt_  = sealedAt;
    }
};

} // namespace xicap::internal
