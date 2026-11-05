#include "xicap/writer.h"
#include "bytes/crc32.h"
#include "format/layout.h"
#include "frame/frame.h"
#include "metadata/codec.h"
#include "policy/check.h"

#include <algorithm>
#include <format>
#include <fstream>
#include <random>
#include <zstd.h>

namespace xicap
{
namespace
{

// The most a packet adds to the plaintext besides its bytes: a varint in each column, and its group's size.
constexpr size_t PACKET_OVERHEAD = 5 + 3 + 2 + 3 + 5 + 3 + 5;
// The most a marker adds besides its text.
constexpr size_t MARKER_OVERHEAD = 5 + 1 + 3;

auto randomCaptureId() -> CaptureId
{
    std::random_device rd;
    CaptureId          id{};
    std::ranges::generate(id, [&]
                          {
                              return static_cast<uint8_t>(rd());
                          });
    return id;
}

} // namespace

struct Writer::State
{
    struct FreeCCtx
    {
        auto operator()(ZSTD_CCtx* c) const noexcept -> void
        {
            ZSTD_freeCCtx(c);
        }
    };

    auto usable() const -> void;
    auto start() -> void;
    auto add(Packet packet) -> void;
    auto endFrame() -> void;
    auto writeFrame() -> void;
    auto emit(std::span<const uint8_t> bytes) -> void;

    std::ofstream                        file;
    Metadata                             metadata;
    FramePolicy                          policy;
    std::unique_ptr<ZSTD_CCtx, FreeCCtx> cctx{ ZSTD_createCCtx() };
    bool                                 started{ false };
    bool                                 closed{ false };
    bool                                 failed{ false }; // a write failed: nothing more may follow

    frame::Frame        frame;
    size_t              frameSize{}; // plaintext, at most
    std::vector<Marker> pendingMarkers;
    size_t              pendingMarkerSize{};
    uint64_t            lastTimestamp{};
    uint64_t            packets{};
};

Writer::Writer(const std::filesystem::path& path, Metadata metadata, FramePolicy policy)
: state_(std::make_unique<State>())
{
    auto& s = *state_;
    policy::check(metadata.policy);
    s.metadata                = std::move(metadata);
    s.metadata.startTimestamp = 0;
    if (s.metadata.captureId == CaptureId{})
    {
        s.metadata.captureId = randomCaptureId();
    }

    policy.maxFrameSize       = std::min<size_t>(policy.maxFrameSize, format::MAX_PLAIN_SIZE);
    policy.maxPacketsPerFrame = std::clamp<uint32_t>(policy.maxPacketsPerFrame, 1, format::MAX_PACKETS);
    policy.windowLog          = std::clamp(policy.windowLog, 10, format::MAX_WINDOW_LOG);
    s.policy                  = policy;
    if (!s.cctx)
    {
        throw Error("xicap: cannot create a zstd compressor");
    }

    ZSTD_CCtx_setParameter(s.cctx.get(), ZSTD_c_compressionLevel, policy.compressionLevel);
    ZSTD_CCtx_setParameter(s.cctx.get(), ZSTD_c_windowLog, policy.windowLog);
    ZSTD_CCtx_setParameter(s.cctx.get(), ZSTD_c_hashLog, policy.hashLog);
    s.file.open(path, std::ios::binary | std::ios::trunc);
    if (!s.file)
    {
        throw Error("xicap: cannot open " + path.string() + " for writing");
    }
}

Writer::~Writer()
{
    try
    {
        close();
    }
    catch (const std::exception&)
    {
        // The file stays cut off: readers read it up to its last whole frame.
    }
}

auto Writer::captureId() const noexcept -> const CaptureId&
{
    return state_->metadata.captureId;
}

auto Writer::write(const OutPacket& packet) -> void
{
    state_->usable();
    const auto stored = applyPolicy(state_->metadata.policy, packet);
    state_->add({ .timestamp = packet.timestamp, .flags = stored.flags, .channel = packet.channel, .opcode = stored.opcode, .data = stored.data, .markers = {} });
}

auto Writer::copy(const Packet& packet) -> void
{
    state_->usable();
    if (frame::isGame(packet.channel) && (packet.data.size() < format::GAME_HEADER_SIZE || format::gameId(packet.data) != packet.opcode))
    {
        throw Error("xicap: a game packet is at least 4 bytes and its header holds its opcode");
    }

    for (const auto& m : packet.markers)
    {
        mark(m.kind, m.text);
    }

    state_->add(packet);
}

auto Writer::mark(MarkerKind kind, std::string_view text) -> void
{
    auto& s = *state_;
    s.usable();
    if (text.size() > UINT16_MAX)
    {
        throw Error("xicap: marker text over 65,535 bytes");
    }

    s.pendingMarkers.push_back({ kind, std::string(text) });
    s.pendingMarkerSize += MARKER_OVERHEAD + text.size();
}

auto Writer::flush() -> void
{
    state_->usable();
    state_->endFrame();
}

auto Writer::close() -> void
{
    auto& s = *state_;
    if (s.closed || s.failed)
    {
        return;
    }

    s.endFrame();
    s.start();
    std::vector<uint8_t> trailer;
    bytes::append(trailer, format::Trailer{ .magic = format::TRAILER_MAGIC, .endTimestamp = s.lastTimestamp, .packetCount = s.packets, .crc = 0 });
    trailer.resize(trailer.size() - sizeof(uint32_t));
    bytes::appendCrc(trailer);
    s.emit(trailer);
    s.closed = true;
    s.file.close();
}

auto Writer::State::usable() const -> void
{
    if (closed)
    {
        throw Error("xicap: the writer is closed");
    }

    if (failed)
    {
        throw Error("xicap: an earlier write failed");
    }
}

// The header and blocks go out with the first frame, once the start time is known.
auto Writer::State::start() -> void
{
    if (!started)
    {
        emit(metadata::encode(metadata));
        started = true;
    }
}

auto Writer::State::add(Packet packet) -> void
{
    if (packets > 0)
    {
        packet.timestamp = std::max(packet.timestamp, lastTimestamp);
    }

    const auto added = PACKET_OVERHEAD + packet.data.size() + pendingMarkerSize;
    if (added > format::MAX_PLAIN_SIZE)
    {
        throw Error("xicap: a packet and the markers before it are over 16 MiB");
    }

    if (!frame.packets.empty() &&
        (frame.packets.size() >= policy.maxPacketsPerFrame || frameSize + added > policy.maxFrameSize ||
         packet.timestamp - frame.packets.front().timestamp >= policy.maxFrameTimeMs || packet.timestamp - lastTimestamp > UINT32_MAX))
    {
        endFrame();
    }

    if (packets == 0)
    {
        metadata.startTimestamp = packet.timestamp;
    }

    packet.markers = pendingMarkers;
    frame.add(packet);
    pendingMarkers.clear();
    pendingMarkerSize = 0;
    frameSize += added;
    lastTimestamp = packet.timestamp;
    packets++;
}

auto Writer::State::endFrame() -> void
{
    if (frame.packets.empty())
    {
        return;
    }

    try
    {
        writeFrame();
    }
    catch (const std::exception&)
    {
        failed = true;
        throw;
    }
}

auto Writer::State::writeFrame() -> void
{
    start();
    const auto           plain = frame::encode(frame);
    std::vector<uint8_t> payload(ZSTD_compressBound(plain.size()));
    auto                 in  = ZSTD_inBuffer{ plain.data(), plain.size(), 0 };
    auto                 buf = ZSTD_outBuffer{ payload.data(), payload.size(), 0 };
    // Flushed, so the frame decodes as soon as it is on disk.
    while (true)
    {
        const auto rc = ZSTD_compressStream2(cctx.get(), &buf, &in, ZSTD_e_flush);
        if (ZSTD_isError(rc))
        {
            throw Error(std::format("xicap: zstd: {}", ZSTD_getErrorName(rc)));
        }

        if (rc == 0)
        {
            break;
        }

        payload.resize(payload.size() * 2);
        buf.dst  = payload.data();
        buf.size = payload.size();
    }

    payload.resize(buf.pos);
    std::vector<uint8_t> out;
    bytes::append(out, format::FrameHeader{
                           .magic         = format::FRAME_MAGIC,
                           .payloadSize   = static_cast<uint32_t>(payload.size()),
                           .plainSize     = static_cast<uint32_t>(plain.size()),
                           .packetCount   = static_cast<uint32_t>(frame.packets.size()),
                           .markerCount   = static_cast<uint32_t>(frame.markers.size()),
                           .baseTimestamp = frame.packets.front().timestamp,
                       });
    out.insert(out.end(), payload.begin(), payload.end());
    bytes::appendCrc(out);
    emit(out);
    frame.clear();
    frameSize = 0;
}

auto Writer::State::emit(std::span<const uint8_t> bytes) -> void
{
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    file.flush();
    if (!file)
    {
        failed = true;
        throw Error("xicap: a write failed");
    }
}

} // namespace xicap
