#pragma once

#include "types.h"
#include "writer.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace xicap
{

// How a transcode signs what it writes. See FORMAT.md, Rewriting a capture.
enum class Signing
{
    // Keep the signer's header, blocks, and signatures; add a seal made with the seed. Format 4 only: a file
    // complete and signed to the end, or cut off.
    Seal,
    // Sign anew with the seed. Any format; a file of another major version gets a SOURCE block naming it.
    Resign,
};

struct TranscodeOptions
{
    FramePolicy policy  = FramePolicy::archive();
    Signing     signing = Signing::Seal;
    SecretSeed  seed{}; // the transcoder's Ed25519 seed
    std::string agent;  // the transcoder's name, for the seal or the source block
    // Resign: the SHA-512 of src as stored, and what to add to the source block's metadata.
    std::array<uint8_t, 64> sourceHash{};
    std::vector<uint8_t>    metadata;
};

struct TranscodeResult
{
    uint64_t packets{};
    uint64_t markers{};
    uint64_t bytesIn{};
    uint64_t bytesOut{};
};

// Rewrites src as format 4 at dst, then reads dst back and checks that it holds the same packets and markers as src
// and that its signatures verify. It writes a file of its own beside dst and renames it to dst only once checked.
// Throws Error, leaving dst as it was: TranscodeRefused for a src the mode does not take, TranscodeMismatch for any
// difference.
auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, const TranscodeOptions& options) -> TranscodeResult;

} // namespace xicap
