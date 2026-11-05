#pragma once

#include "metadata.h"
#include "stream_reader.h"
#include "types.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

namespace xicap
{

// Reads a capture file. A complete file is read whole or refused; a cut-off one reads up to its first frame that is
// not whole and valid.
class Reader
{
public:
    // Reads the header and blocks. Throws Error for a file that must be refused.
    explicit Reader(const std::filesystem::path& path);

    [[nodiscard]] auto metadata() const noexcept -> const Metadata&
    {
        return stream_.metadata();
    }

    // True when the file ends with a valid trailer.
    [[nodiscard]] auto complete() const noexcept -> bool
    {
        return complete_;
    }

    // The trailer's end time, or 0 in a cut-off file.
    [[nodiscard]] auto endTimestamp() const noexcept -> uint64_t
    {
        return endTimestamp_;
    }

    [[nodiscard]] auto packetCount() const noexcept -> uint64_t
    {
        return packetCount_;
    }

    // The bytes read so far, up to the end of the frame that holds the last packet read.
    [[nodiscard]] auto bytesRead() const noexcept -> uint64_t
    {
        return stream_.bytesRead();
    }

    // The next packet; false at the end of the capture. Throws Error for a complete file with a bad frame.
    auto next(Packet& packet) -> bool;

    class Iterator
    {
    public:
        using value_type      = Packet;
        using difference_type = std::ptrdiff_t;

        explicit Iterator(Reader& reader);
        auto operator*() const noexcept -> const Packet&
        {
            return packet_;
        }

        auto operator->() const noexcept -> const Packet*
        {
            return &packet_;
        }

        auto operator++() -> Iterator&;
        auto operator++(int) -> void
        {
            ++*this;
        }

        auto operator==(std::default_sentinel_t) const noexcept -> bool
        {
            return done_;
        }

    private:
        Reader* reader_;
        Packet  packet_;
        bool    done_{ false };
    };

    auto begin() -> Iterator
    {
        return Iterator(*this);
    }

    [[nodiscard]] auto end() const noexcept -> std::default_sentinel_t
    {
        return {};
    }

private:
    auto pushChunk() -> bool;

    std::ifstream          file_;
    StreamReader           stream_;
    std::vector<std::byte> chunk_;
    bool                   complete_{ false };
    uint64_t               endTimestamp_{};
    uint64_t               packetCount_{};
};

} // namespace xicap
