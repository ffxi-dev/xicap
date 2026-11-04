#pragma once

#include "types.h"
#include "writer.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace xicap
{

// How a transcode signs what it writes. See FORMAT.md, Rewriting a capture.
enum class Signing
{
    // Keep the signer's header, blocks, and signatures; add a seal made with the seed. Takes a file complete and
    // signed to the end, a cut-off one, or a sealed one whose end was never signed; refuses one with a signature that
    // fails.
    Seal,
    // The signer writes its own file again: the seed must be the one the header's key comes from. Takes a file
    // complete and signed to the end. With signer set, the file's SOURCE_SIGNER block becomes that one.
    Reissue,
};

struct TranscodeOptions
{
    FramePolicy policy  = FramePolicy::archive();
    Signing     signing = Signing::Seal;
    SecretSeed  seed{}; // the transcoder's Ed25519 seed
    std::string agent;  // Seal: the seal's agent, the transcoder with its version
    // Reissue: the signed capture the file's packets came from. The file must have a SOURCE block.
    std::optional<SourceSigner> signer;
};

struct TranscodeResult
{
    uint64_t packets{};
    uint64_t markers{};
    uint64_t bytesIn{};
    uint64_t bytesOut{};
};

// Rewrites src at dst with other frames and compression, then reads dst back and checks that it holds the same
// packets and markers as src and that its signatures verify. The packets and the capture id stay; the bytes depend
// on the zstd version. It writes a file of its own beside dst and renames it to dst only once checked. Throws Error,
// leaving dst as it was: TranscodeRefused for a src the mode does not take, TranscodeMismatch for any difference.
auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, const TranscodeOptions& options) -> TranscodeResult;

// Writes the packets of source whose frame does not end within its first fromByte bytes, up to its last intact frame,
// with the markers before them, as a new capture at out that continues source: a new capture id, source's id as
// previousCaptureId, startContext MidSession, and source's agent, client, character, clock, origin, network,
// recording mode, exclusion policy and source block. Packets are copied as stored. Signed with seed and written with policy. Returns
// the packets written; with none, it writes no file. Throws Error, leaving out as it was. For a recorder whose upload
// was cut off: fromByte is what the archive holds.
auto continueFrom(const std::filesystem::path& source, uint64_t fromByte, const std::filesystem::path& out, const SecretSeed& seed, FramePolicy policy = FramePolicy::live()) -> uint64_t;

} // namespace xicap
