#pragma once

#include "types.h"
#include "writer.h"

#include <cstdint>
#include <filesystem>
#include <string>

namespace xicap
{

// A transcode seals what it writes: it keeps the signer's header, blocks, and signatures, and adds a seal made with
// the seed. It takes a file complete and signed to the end, a cut-off one, or a sealed one whose end was never signed,
// and refuses one with a signature that fails. See FORMAT.md, Rewriting a capture.
struct TranscodeOptions
{
    FramePolicy policy = FramePolicy::archive();
    SecretSeed  seed{}; // the sealer's Ed25519 seed
    std::string agent;  // the seal's agent, the sealer with its version
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
// exclusion policy and source block. Packets are copied as stored. Signed with seed and written with policy. Returns
// the packets written; with none, it writes no file. Throws Error, leaving out as it was. For a recorder whose upload
// was cut off: fromByte is what the archive holds.
auto continueFrom(const std::filesystem::path& source, uint64_t fromByte, const std::filesystem::path& out, const SecretSeed& seed, FramePolicy policy = FramePolicy::live()) -> uint64_t;

} // namespace xicap
