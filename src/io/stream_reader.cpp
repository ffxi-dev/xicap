#include "xicap/stream_reader.h"
#include "bytes/crc32.h"
#include "frame/decoder.h"
#include "metadata/codec.h"

#include <algorithm>
#include <optional>
#include <utility>

namespace xicap
{

struct StreamReader::State
{
    enum class Stage
    {
        Header,
        Blocks,
        Frames,
        Complete,
        Stopped,
    };

    auto parse() -> void;
    auto parseFrame(std::span<const uint8_t> avail) -> bool;

    Stage                         stage{ Stage::Header };
    std::vector<uint8_t>          buffer;
    size_t                        pos{};
    uint64_t                      dropped{}; // bytes read and erased from the front of buffer
    Metadata                      metadata;
    uint8_t                       blocksLeft{};
    bool                          haveSource{ false };
    std::optional<frame::Decoder> decoder;
    frame::Frame                  frame;
    size_t                        nextPacket{};
    uint64_t                      packets{};
    uint64_t                      lastTimestamp{};
};

StreamReader::StreamReader()
: state_(std::make_unique<State>())
{
}

StreamReader::~StreamReader() = default;

auto StreamReader::ready() const noexcept -> bool
{
    return state_->decoder.has_value();
}

auto StreamReader::complete() const noexcept -> bool
{
    return state_->stage == State::Stage::Complete;
}

auto StreamReader::stopped() const noexcept -> bool
{
    return state_->stage == State::Stage::Stopped;
}

auto StreamReader::metadata() const noexcept -> const Metadata&
{
    return state_->metadata;
}

auto StreamReader::bytesRead() const noexcept -> uint64_t
{
    return state_->dropped + state_->pos;
}

auto StreamReader::push(std::span<const std::byte> bytes) -> void
{
    auto& s = *state_;
    if (s.stage == State::Stage::Stopped || bytes.empty())
    {
        return;
    }

    // Erase what was read once it is most of the buffer, so each byte moves a bounded number of times.
    if (s.pos > s.buffer.size() / 2)
    {
        s.buffer.erase(s.buffer.begin(), s.buffer.begin() + static_cast<std::ptrdiff_t>(s.pos));
        s.dropped += s.pos;
        s.pos = 0;
    }

    s.buffer.resize(s.buffer.size() + bytes.size());
    std::ranges::copy(bytes, std::as_writable_bytes(std::span{ s.buffer }).last(bytes.size()).begin());
    s.parse();
}

auto StreamReader::next(Packet& packet) -> bool
{
    auto& s = *state_;
    if (s.nextPacket >= s.frame.packets.size())
    {
        s.parse();
        if (s.nextPacket >= s.frame.packets.size())
        {
            return false;
        }
    }

    packet = s.frame.packet(s.nextPacket++);
    return true;
}

// Reads as far as the bytes allow, and stops once a frame is decoded and waiting to be read.
auto StreamReader::State::parse() -> void
{
    while (true)
    {
        const auto avail = std::span{ buffer }.subspan(pos);
        switch (stage)
        {
            case Stage::Header:
                if (avail.size() < sizeof(format::Header))
                {
                    return;
                }

                blocksLeft = metadata::readHeader(avail, metadata);
                pos += sizeof(format::Header);
                stage = Stage::Blocks;
                break;
            case Stage::Blocks:
            {
                if (blocksLeft == 0)
                {
                    decoder.emplace();
                    stage = Stage::Frames;
                    break;
                }

                if (avail.size() < sizeof(format::BlockHeader))
                {
                    return;
                }

                const auto size = metadata::blockSize(avail);
                if (avail.size() < size)
                {
                    return;
                }

                const auto type = metadata::readBlock(avail.first(static_cast<size_t>(size)), metadata);
                if (type == format::BLOCK_SOURCE && std::exchange(haveSource, true))
                {
                    throw Error("xicap: a second source block");
                }

                pos += static_cast<size_t>(size);
                blocksLeft--;
                break;
            }
            case Stage::Frames:
                if (nextPacket < frame.packets.size() || !parseFrame(avail))
                {
                    return;
                }

                break;
            case Stage::Complete:
                if (!avail.empty())
                {
                    throw Error("xicap: bytes after the trailer");
                }

                return;
            case Stage::Stopped:
                return;
        }
    }
}

// Reads the frame or trailer at the start of avail. False when it needs more bytes or stops.
auto StreamReader::State::parseFrame(std::span<const uint8_t> avail) -> bool
{
    if (avail.size() < sizeof(uint32_t))
    {
        return false;
    }

    const auto magic = bytes::load<uint32_t>(avail);
    const auto stop  = [this]
    {
        stage = Stage::Stopped;
        frame.clear();
        return false;
    };

    if (magic == format::TRAILER_MAGIC)
    {
        if (avail.size() < sizeof(format::Trailer))
        {
            return false;
        }

        if (!bytes::endsWithCrc(avail.first(sizeof(format::Trailer))))
        {
            return stop();
        }

        const auto t = bytes::load<format::Trailer>(avail);
        if (t.packetCount != packets || t.endTimestamp != lastTimestamp)
        {
            throw Error("xicap: the trailer disagrees with the frames");
        }

        pos += sizeof(t);
        stage = Stage::Complete;
        return true;
    }

    if (magic != format::FRAME_MAGIC)
    {
        return stop();
    }

    if (avail.size() < sizeof(format::FrameHeader))
    {
        return false;
    }

    const auto h = bytes::load<format::FrameHeader>(avail);
    if (h.payloadSize > format::MAX_PAYLOAD_SIZE)
    {
        return stop();
    }

    const auto size = sizeof(h) + size_t{ h.payloadSize } + sizeof(uint32_t);
    if (avail.size() < size)
    {
        return false;
    }

    if (!bytes::endsWithCrc(avail.first(size)))
    {
        return stop();
    }

    try
    {
        decoder->decode(h, avail.subspan(sizeof(h), h.payloadSize), frame);
    }
    catch (const Error&)
    {
        return stop();
    }

    pos += size;
    nextPacket = 0;
    packets += frame.packets.size();
    lastTimestamp = frame.packets.back().timestamp;
    return true;
}

} // namespace xicap
