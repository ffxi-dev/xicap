#include "xicap/stream_reader.h"
#include "internal/crc32.h"
#include "internal/decoder.h"

#include <algorithm>
#include <cstring>

namespace xicap
{

StreamReader::StreamReader()
: start_(std::make_unique<internal::Start>())
, frame_(std::make_unique<internal::DecodedFrame>())
{
}

StreamReader::~StreamReader() = default;

auto StreamReader::ready() const noexcept -> bool
{
    return decoder_ != nullptr;
}

auto StreamReader::stopped() const noexcept -> bool
{
    return state_ == State::Stopped;
}

auto StreamReader::unreadBytes() const noexcept -> uint64_t
{
    return buffer_.size() - pos_ + dropped_;
}

auto StreamReader::header() const noexcept -> const Header&
{
    return start_->header;
}

auto StreamReader::clientVersion() const -> std::string
{
    return internal::textOf(start_->header.clientVersion);
}

auto StreamReader::captureAgent() const -> std::string
{
    return internal::textOf(start_->header.captureAgent);
}

auto StreamReader::policy() const noexcept -> const ExclusionPolicy&
{
    return start_->policy;
}

auto StreamReader::push(std::span<const uint8_t> bytes) -> void
{
    if (state_ == State::Stopped)
    {
        dropped_ += bytes.size(); // counted, not kept: nothing after a stop is read
        return;
    }
    // Drop what has been read once it is most of the buffer, so each byte moves a bounded number of times.
    if (pos_ > 0 && pos_ >= buffer_.size() / 2)
    {
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(pos_));
        pos_ = 0;
    }
    buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
    parse();
}

auto StreamReader::next(ReadPacket& packet) -> bool
{
    if (packetPos_ >= frame_->packets.size())
    {
        parse();
        if (packetPos_ >= frame_->packets.size())
        {
            return false;
        }
    }
    packet = frame_->read(packetPos_++);
    return true;
}

// Reads as far as the bytes allow, stopping once a packet frame is decoded and waiting to be read.
auto StreamReader::parse() -> void
{
    while (true)
    {
        const std::span<const uint8_t> avail{ buffer_.data() + pos_, buffer_.size() - pos_ };
        switch (state_)
        {
            case State::Header:
            {
                if (avail.size() < HEADER_SIZE)
                {
                    return;
                }
                const auto size = internal::headerSize(avail.first(HEADER_SIZE));
                if (avail.size() < size)
                {
                    return;
                }
                internal::readHeader(avail.first(size), *start_);
                pos_ += size;
                state_ = State::Blocks;
                break;
            }
            case State::Blocks:
            {
                if (nextBlock_ == start_->header.extensionCount)
                {
                    internal::finishBlocks(*start_);
                    decoder_ = std::make_unique<internal::Decoder>();
                    state_   = State::Frames;
                    break;
                }
                if (avail.size() < sizeof(ExtensionBlockHeader))
                {
                    return;
                }
                const auto size = internal::blockSize(avail);
                if (avail.size() < size)
                {
                    return;
                }
                internal::readBlock(avail.first(static_cast<size_t>(size)), nextBlock_++, *start_);
                start_->blocks.clear(); // only the reader's verify needs them
                pos_ += static_cast<size_t>(size);
                break;
            }
            case State::Frames:
            {
                if (packetPos_ < frame_->packets.size())
                {
                    return;
                }
                frame_->clear();
                packetPos_ = 0;
                internal::FrameInfo info;
                if (avail.size() < sizeof(FrameHeader))
                {
                    if (avail.size() >= 4 && std::memcmp(avail.data(), "XCFR", 4) != 0)
                    {
                        state_ = State::Stopped;
                    }
                    return;
                }
                if (!internal::parseFrameHeader(avail, info) || info.payloadSize > internal::MAX_PAYLOAD_SIZE)
                {
                    state_ = State::Stopped;
                    return;
                }
                const uint64_t size = sizeof(FrameHeader) + uint64_t{ info.payloadSize } + sizeof(uint32_t);
                if (avail.size() < size)
                {
                    return;
                }
                const auto frame = avail.first(static_cast<size_t>(size));
                if (!internal::endsWithCrc(frame))
                {
                    state_ = State::Stopped;
                    return;
                }
                internal::checkKind(info.kind);
                if (info.kind == FrameKind::Packets)
                {
                    try
                    {
                        decoder_->decode(info, frame.subspan(sizeof(FrameHeader), info.payloadSize), *frame_);
                    }
                    catch (const Error& error)
                    {
                        if (error.code() == ErrorCode::UnknownPacketFlag)
                        {
                            throw;
                        }
                        frame_->clear();
                        state_ = State::Stopped;
                        return;
                    }
                }
                pos_ += frame.size();
                characterMismatch_ = characterMismatch_ || internal::namesOtherCharacter(start_->header, *frame_);
                break;
            }
            case State::Stopped:
                return;
        }
    }
}

} // namespace xicap
