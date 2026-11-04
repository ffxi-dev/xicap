#pragma once

#include "metadata.h"
#include "types.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace xicap
{

// Reads a capture as its bytes arrive, as a download does. It holds the frame being received and the zstd history,
// nothing more.
class StreamReader
{
public:
    StreamReader();
    ~StreamReader();
    StreamReader(const StreamReader&)                    = delete;
    StreamReader(StreamReader&&)                         = delete;
    auto operator=(const StreamReader&) -> StreamReader& = delete;
    auto operator=(StreamReader&&) -> StreamReader&      = delete;

    // The capture's next bytes, in order. Throws Error for a capture that must be refused.
    auto push(std::span<const std::byte> bytes) -> void;
    // The next packet whose frame has arrived whole; false until another has.
    auto next(Packet& packet) -> bool;

    // The header and blocks are read: metadata() holds them.
    [[nodiscard]] auto ready() const noexcept -> bool;
    // The trailer is read: every packet has been.
    [[nodiscard]] auto complete() const noexcept -> bool;
    // The reader met bytes that are neither a whole, valid frame nor the trailer, and reads nothing more.
    [[nodiscard]] auto stopped() const noexcept -> bool;
    [[nodiscard]] auto metadata() const noexcept -> const Metadata&;
    // Input bytes read: through the last frame decoded, or the trailer.
    [[nodiscard]] auto bytesRead() const noexcept -> uint64_t;

private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace xicap
