#pragma once

#include "enums/chat.h"
#include "metadata.h"
#include "types.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string_view>

namespace xicap
{

// How a writer frames and compresses packets. See FORMAT.md, Writer rules.
struct FramePolicy
{
    size_t   maxFrameSize{ size_t{ 64 } * 1024 }; // plaintext bytes, at most 16 MiB
    uint32_t maxPacketsPerFrame{ 1000 };
    uint64_t maxFrameTimeMs{ 5000 };
    int      compressionLevel{ 7 };
    int      windowLog{ 21 }; // at most 23
    int      hashLog{ 19 };   // 0 for the level's own; sets most of the compressor's memory

    // What a recorder writes: about 5.5 MB of compressor.
    static auto live() -> FramePolicy
    {
        return {};
    }

    // What an archive writes: smaller files, written more slowly.
    static auto archive() -> FramePolicy
    {
        return {
            .maxFrameSize       = size_t{ 1024 } * 1024,
            .maxPacketsPerFrame = 1024 * 1024,
            .maxFrameTimeMs     = UINT64_MAX,
            .compressionLevel   = 19,
            .windowLog          = 23,
            .hashLog            = 0,
        };
    }
};

// Writes a capture. Each frame is on disk, and readable, once written; close() adds the trailer.
class Writer
{
public:
    Writer(const std::filesystem::path& path, Metadata metadata, FramePolicy policy = FramePolicy::live(), Chat chat = Chat::Redact);
    ~Writer();
    Writer(const Writer&)                    = delete;
    Writer(Writer&&)                         = delete;
    auto operator=(const Writer&) -> Writer& = delete;
    auto operator=(Writer&&) -> Writer&      = delete;

    // Zeroes chat text unless the writer keeps chat, then adds the packet.
    auto write(const OutPacket& packet) -> void;
    // Adds a packet as a reader yielded it, flags and markers included, unchanged.
    auto copy(const Packet& packet) -> void;
    // Places a marker just before the next packet. One with no packet after it is dropped.
    auto mark(MarkerKind kind, std::string_view text = {}) -> void;
    // Ends the frame being built, so its packets are on disk.
    auto flush() -> void;
    // Writes the last frame and the trailer.
    auto close() -> void;

    [[nodiscard]] auto captureId() const noexcept -> const CaptureId&;

private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace xicap
