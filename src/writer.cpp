#include "xicap/writer.h"
#include "columns.h"
#include "crc32.h"
#include "format.h"
#include "metadata_codec.h"
#include "policy_check.h"

#include <algorithm>
#include <cstring>
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
    while (id == CaptureId{})
    {
        std::ranges::generate(id, [&]
                              {
                                  return static_cast<uint8_t>(rd());
                              });
    }

    return id;
}

template <typename T>
auto append(std::vector<uint8_t>& out, const T& value) -> void
{
    const auto* p = reinterpret_cast<const uint8_t*>(&value);
    out.insert(out.end(), p, p + sizeof(T));
}

} // namespace

struct Writer::State
{
    struct FramePacket
    {
        uint64_t timestamp{};
        uint16_t flags{};
        uint8_t  channel{};
        uint16_t opcode{};
        size_t   offset{};
        size_t   length{};
    };

    struct FrameMarker
    {
        uint32_t packetIndex{};
        Marker   marker;
    };

    struct FreeCCtx
    {
        auto operator()(ZSTD_CCtx* c) const noexcept -> void
        {
            ZSTD_freeCCtx(c);
        }
    };

    auto usable() const -> void;
    auto start() -> void;
    auto add(uint64_t timestamp, uint16_t flags, uint8_t channel, uint16_t opcode, std::span<const uint8_t> data) -> void;
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

    std::vector<uint8_t>     frameBytes;
    std::vector<FramePacket> framePackets;
    std::vector<FrameMarker> frameMarkers;
    std::vector<Marker>      pendingMarkers;
    size_t                   frameSize{}; // plaintext, at most
    size_t                   pendingMarkerSize{};
    uint64_t                 lastTimestamp{};
    uint64_t                 packets{};
    std::vector<uint8_t>     out;
};

Writer::Writer(const std::filesystem::path& path, Metadata metadata, FramePolicy policy)
: state_(std::make_unique<State>())
{
    auto& s = *state_;
    internal::checkPolicy(metadata.policy);
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
    state_->add(packet.timestamp, stored.flags, packet.channel, stored.opcode, { reinterpret_cast<const uint8_t*>(stored.data.data()), stored.data.size() });
}

auto Writer::copy(const Packet& packet) -> void
{
    state_->usable();
    if (internal::isGame(packet.channel) && packet.data.size() < format::GAME_HEADER_SIZE)
    {
        throw Error("xicap: a game packet is at least 4 bytes");
    }
    for (const auto& m : packet.markers)
    {
        mark(m.kind, m.text);
    }
    state_->add(packet.timestamp, packet.flags, packet.channel, packet.opcode, { reinterpret_cast<const uint8_t*>(packet.data.data()), packet.data.size() });
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
    auto t = format::Trailer{ .magic = format::TRAILER_MAGIC, .endTimestamp = s.lastTimestamp, .packetCount = s.packets, .crc = 0 };
    t.crc  = internal::crc32({ reinterpret_cast<const uint8_t*>(&t), offsetof(format::Trailer, crc) });
    s.emit({ reinterpret_cast<const uint8_t*>(&t), sizeof(t) });
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
        emit(internal::encodeMetadata(metadata));
        started = true;
    }
}

auto Writer::State::add(uint64_t timestamp, uint16_t flags, uint8_t channel, uint16_t opcode, std::span<const uint8_t> data) -> void
{
    // Timestamps never go backwards.
    if (packets > 0)
    {
        timestamp = std::max(timestamp, lastTimestamp);
    }
    const auto added = PACKET_OVERHEAD + data.size() + pendingMarkerSize;
    if (added > format::MAX_PLAIN_SIZE)
    {
        throw Error("xicap: a packet and the markers before it are over 16 MiB");
    }
    if (!framePackets.empty() &&
        (framePackets.size() >= policy.maxPacketsPerFrame || frameSize + added > policy.maxFrameSize ||
         timestamp - framePackets.front().timestamp >= policy.maxFrameTimeMs || timestamp - lastTimestamp > UINT32_MAX))
    {
        endFrame();
    }
    if (packets == 0)
    {
        metadata.startTimestamp = timestamp;
    }
    for (auto& marker : pendingMarkers)
    {
        frameMarkers.push_back({ static_cast<uint32_t>(framePackets.size()), std::move(marker) });
    }
    pendingMarkers.clear();
    pendingMarkerSize = 0;
    framePackets.push_back({ .timestamp = timestamp, .flags = flags, .channel = channel, .opcode = opcode, .offset = frameBytes.size(), .length = data.size() });
    frameBytes.insert(frameBytes.end(), data.begin(), data.end());
    frameSize += added;
    lastTimestamp = timestamp;
    packets++;
}

auto Writer::State::endFrame() -> void
{
    if (framePackets.empty())
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
    std::vector<internal::Record> records;
    for (const auto& p : framePackets)
    {
        records.push_back({ .timestamp = p.timestamp, .flags = p.flags, .channel = p.channel, .opcode = p.opcode, .data = std::span{ frameBytes }.subspan(p.offset, p.length) });
    }
    std::vector<internal::MarkerRecord> markers;
    for (const auto& m : frameMarkers)
    {
        markers.push_back({ .packetIndex = m.packetIndex, .kind = m.marker.kind, .text = m.marker.text });
    }
    const auto plain = internal::encodeColumns(records, markers);

    constexpr auto head = sizeof(format::FrameHeader);
    out.resize(head + ZSTD_compressBound(plain.size()));
    auto in  = ZSTD_inBuffer{ plain.data(), plain.size(), 0 };
    auto buf = ZSTD_outBuffer{ out.data() + head, out.size() - head, 0 };
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
        out.resize(out.size() * 2);
        buf.dst  = out.data() + head;
        buf.size = out.size() - head;
    }
    const auto header = format::FrameHeader{
        .magic         = format::FRAME_MAGIC,
        .payloadSize   = static_cast<uint32_t>(buf.pos),
        .plainSize     = static_cast<uint32_t>(plain.size()),
        .packetCount   = static_cast<uint32_t>(framePackets.size()),
        .markerCount   = static_cast<uint32_t>(frameMarkers.size()),
        .baseTimestamp = framePackets.front().timestamp,
    };
    std::memcpy(out.data(), &header, head);
    out.resize(head + buf.pos);
    append(out, internal::crc32(out));
    emit(out);

    frameBytes.clear();
    framePackets.clear();
    frameMarkers.clear();
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
