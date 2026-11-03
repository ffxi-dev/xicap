#pragma once

#include "constants.h"
#include "types.h"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace xicap
{

namespace internal
{
class Decoder;
struct DecodedFrame;
struct Start;
} // namespace internal

// Reads a capture of format 3 or 4 as its bytes arrive, as a download does. It holds the frame being received and
// one zstd stream's history, nothing more. It stops at the first bytes that are not a whole, valid frame: in a
// complete file, the footer.
class StreamReader
{
public:
    StreamReader();
    ~StreamReader();

    StreamReader(const StreamReader&)                    = delete;
    StreamReader(StreamReader&&)                         = delete;
    auto operator=(const StreamReader&) -> StreamReader& = delete;
    auto operator=(StreamReader&&) -> StreamReader&      = delete;

    // The capture's next bytes, in order. Throws xicap::Error when the file must be refused.
    auto push(std::span<const uint8_t> bytes) -> void;
    // The next packet whose frame has arrived whole; false until another one has. The packet's spans stay valid
    // until the next call to next or push.
    auto next(ReadPacket& packet) -> bool;

    // True once the header and extension blocks are read; the accessors below work from then on.
    [[nodiscard]] auto ready() const noexcept -> bool;
    // True once the reader has met bytes that are not a whole, valid frame. It reads nothing after them.
    [[nodiscard]] auto stopped() const noexcept -> bool;
    // Bytes pushed but not read: a frame still arriving, or whatever came after the stop.
    [[nodiscard]] auto unreadBytes() const noexcept -> uint64_t;
    // A zone-in read so far names a character other than the header's.
    [[nodiscard]] auto characterMismatch() const noexcept -> bool
    {
        return characterMismatch_;
    }

    [[nodiscard]] auto header() const noexcept -> const Header&;
    [[nodiscard]] auto versionMajor() const noexcept -> uint8_t
    {
        return header().versionMajor;
    }
    [[nodiscard]] auto startTimestamp() const noexcept -> uint64_t
    {
        return header().startTimestamp;
    }
    [[nodiscard]] auto origin() const noexcept -> Origin
    {
        return header().origin;
    }
    [[nodiscard]] auto character() const noexcept -> const CharacterIdentity&
    {
        return header().character;
    }
    [[nodiscard]] auto clientVersion() const -> std::string;
    [[nodiscard]] auto captureAgent() const -> std::string;
    [[nodiscard]] auto policy() const noexcept -> const ExclusionPolicy&;

private:
    enum class State
    {
        Header,
        Blocks,
        Frames,
        Stopped,
    };

    auto parse() -> void;

    State                                   state_{ State::Header };
    std::vector<uint8_t>                    buffer_;
    size_t                                  pos_{ 0 };
    uint32_t                                nextBlock_{ 0 };
    bool                                    characterMismatch_{ false };
    size_t                                  packetPos_{ 0 };
    std::unique_ptr<internal::Start>        start_;
    std::unique_ptr<internal::Decoder>      decoder_;
    std::unique_ptr<internal::DecodedFrame> frame_;
};

} // namespace xicap
