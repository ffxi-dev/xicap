#include "xicap/stream_reader.h"
#include "frame/decoder.h"
#include "metadata/codec.h"

#include <algorithm>
#include <string>

namespace xicap
{

struct StreamReader::State
{
    enum class Stage : uint8_t
    {
        Header,
        Blocks,
        Frames,
        Complete,
        Stopped,
    };

    auto parse() -> void;
    auto parseFrame(std::span<const uint8_t> avail) -> bool;
    auto stop(std::string_view why) -> bool;

    Stage                stage{ Stage::Header };
    std::vector<uint8_t> buffer;
    size_t               pos{};
    uint64_t             dropped{}; // bytes read and erased from the front of buffer
    Metadata             metadata;
    uint8_t              blocksLeft{};
    frame::Decoder       decoder;
    frame::Frame         frame;
    size_t               nextPacket{};
    uint64_t             packetCount{};
    std::string          stopReason;
};

StreamReader::StreamReader()
: state_(std::make_unique<State>())
{
}

StreamReader::~StreamReader() = default;

auto StreamReader::ready() const noexcept -> bool
{
    return state_->stage != State::Stage::Header && state_->stage != State::Stage::Blocks;
}

auto StreamReader::complete() const noexcept -> bool
{
    return state_->stage == State::Stage::Complete;
}

auto StreamReader::stopped() const noexcept -> bool
{
    return state_->stage == State::Stage::Stopped;
}

auto StreamReader::stopReason() const noexcept -> std::string_view
{
    return state_->stopReason;
}

auto StreamReader::metadata() const noexcept -> const Metadata&
{
    return state_->metadata;
}

auto StreamReader::bytesRead() const noexcept -> uint64_t
{
    return state_->dropped + state_->pos;
}

auto StreamReader::push(const std::span<const uint8_t> bytes) -> void
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

    s.buffer.insert(s.buffer.end(), bytes.begin(), bytes.end());
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

                metadata::readBlock(avail.first(static_cast<size_t>(size)), metadata);
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
auto StreamReader::State::parseFrame(const std::span<const uint8_t> avail) -> bool
{
    if (avail.size() < sizeof(uint32_t))
    {
        return false;
    }

    const auto magic = bytes::load<uint32_t>(avail);
    if (magic == format::TRAILER_MAGIC)
    {
        if (avail.size() < sizeof(format::Trailer))
        {
            return false;
        }

        const auto t = format::readTrailer(avail);
        if (!t)
        {
            return stop("xicap: trailer CRC mismatch");
        }

        if (t->packetCount != packetCount || t->endTimestamp != decoder.lastTimestamp())
        {
            throw Error("xicap: the trailer disagrees with the frames");
        }

        pos += sizeof(format::Trailer);
        stage = Stage::Complete;
        return true;
    }

    if (magic != format::FRAME_MAGIC)
    {
        return stop("xicap: bad frame: no frame magic");
    }

    if (avail.size() < sizeof(format::FrameHeader))
    {
        return false;
    }

    const auto h = bytes::load<format::FrameHeader>(avail);
    if (h.payloadSize > format::MAX_PAYLOAD_SIZE)
    {
        return stop("xicap: bad frame: payload over 17 MiB");
    }

    const auto size = sizeof(h) + size_t{ h.payloadSize } + sizeof(uint32_t);
    if (avail.size() < size)
    {
        return false;
    }

    if (!bytes::endsWithCrc(avail.first(size)))
    {
        return stop("xicap: bad frame: CRC mismatch");
    }

    try
    {
        decoder.decode(h, avail.subspan(sizeof(h), h.payloadSize), frame);
    }
    catch (const Error& e)
    {
        return stop(e.what());
    }

    pos += size;
    nextPacket = 0;
    packetCount += frame.packets.size();
    return true;
}

auto StreamReader::State::stop(const std::string_view why) -> bool
{
    stage      = Stage::Stopped;
    stopReason = why;
    frame.clear();
    return false;
}

} // namespace xicap
