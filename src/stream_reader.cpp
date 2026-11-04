#include "xicap/stream_reader.h"
#include "crc32.h"
#include "frame_decoder.h"
#include "metadata_codec.h"

#include <cstring>
#include <optional>

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

    Stage                                 stage{ Stage::Header };
    std::vector<uint8_t>                  buffer;
    size_t                                pos{};
    uint64_t                              dropped{}; // bytes read and erased from the front of buffer
    Metadata                              metadata;
    uint8_t                               blocksLeft{};
    int                                   policies{};
    int                                   sources{};
    std::optional<internal::FrameDecoder> decoder;
    internal::DecodedFrame                frame;
    size_t                                nextPacket{};
    uint64_t                              packets{};
    uint64_t                              lastTimestamp{};
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
    const auto* p = reinterpret_cast<const uint8_t*>(bytes.data());
    s.buffer.insert(s.buffer.end(), p, p + bytes.size());
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
                blocksLeft = internal::readHeader(avail, metadata);
                pos += sizeof(format::Header);
                stage = Stage::Blocks;
                break;
            case Stage::Blocks:
            {
                if (blocksLeft == 0)
                {
                    if (policies != 1)
                    {
                        throw Error("xicap: no exclusion policy block");
                    }
                    decoder.emplace();
                    stage = Stage::Frames;
                    break;
                }
                if (avail.size() < sizeof(format::BlockHeader))
                {
                    return;
                }
                const auto size = internal::blockSize(avail);
                if (avail.size() < size)
                {
                    return;
                }
                const auto type = internal::readBlock(avail.first(static_cast<size_t>(size)), metadata);
                policies += static_cast<int>(type == format::BLOCK_POLICY);
                sources += static_cast<int>(type == format::BLOCK_SOURCE);
                if (policies > 1 || sources > 1)
                {
                    throw Error("xicap: a second exclusion policy or source block");
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

// Reads the frame or trailer at the start of avail. False when it needs more bytes, or stops.
auto StreamReader::State::parseFrame(std::span<const uint8_t> avail) -> bool
{
    uint32_t magic = 0;
    if (avail.size() < sizeof(magic))
    {
        return false;
    }
    std::memcpy(&magic, avail.data(), sizeof(magic));
    const auto stop = [this]
    {
        stage = Stage::Stopped;
        frame.packets.clear();
        return false;
    };

    if (magic == format::TRAILER_MAGIC)
    {
        format::Trailer t{};
        if (avail.size() < sizeof(t))
        {
            return false;
        }
        std::memcpy(&t, avail.data(), sizeof(t));
        if (internal::crc32(avail.first(offsetof(format::Trailer, crc))) != t.crc)
        {
            return stop();
        }
        if (t.packetCount != packets || t.endTimestamp != lastTimestamp)
        {
            throw Error("xicap: the trailer disagrees with the frames");
        }
        pos += sizeof(t);
        stage = Stage::Complete;
        return false;
    }

    format::FrameHeader h{};
    if (magic != format::FRAME_MAGIC)
    {
        return stop();
    }
    if (avail.size() < sizeof(h))
    {
        return false;
    }
    std::memcpy(&h, avail.data(), sizeof(h));
    if (h.payloadSize > format::MAX_PAYLOAD_SIZE)
    {
        return stop();
    }
    const auto size = sizeof(h) + size_t{ h.payloadSize } + sizeof(uint32_t);
    if (avail.size() < size)
    {
        return false;
    }
    uint32_t crc = 0;
    std::memcpy(&crc, avail.data() + size - sizeof(crc), sizeof(crc));
    if (internal::crc32(avail.first(size - sizeof(crc))) != crc)
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
