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

    // True once the header and blocks are read, so that metadata() holds them.
    [[nodiscard]] auto ready() const noexcept -> bool;
    // True once the trailer is read, which comes after every packet.
    [[nodiscard]] auto complete() const noexcept -> bool;
    // True once the reader has met bytes that are neither a whole, valid frame nor a trailer; it reads nothing more.
    [[nodiscard]] auto stopped() const noexcept -> bool;
    [[nodiscard]] auto metadata() const noexcept -> const Metadata&;
    // The bytes read so far, up to the end of the last frame decoded or of the trailer.
    [[nodiscard]] auto bytesRead() const noexcept -> uint64_t;

private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace xicap
