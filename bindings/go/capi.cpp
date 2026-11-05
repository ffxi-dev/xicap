#include "capi.h"

#include "xicap/xicap.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <vector>

static_assert(XICAP_HEADER_SIZE == xicap::HEADER_SIZE);

namespace
{

template <typename F>
auto guarded(F&& f) -> char*
{
    try
    {
        f();
        return nullptr;
    }
    catch (const std::exception& e)
    {
        return strdup(e.what());
    }
}

auto toC(const xicap::Metadata& m) -> xicap_metadata
{
    const auto* const s   = m.source ? &*m.source : nullptr;
    auto              out = xicap_metadata{
        .capture_id            = {},
        .previous_capture_id   = {},
        .start_timestamp       = m.startTimestamp,
        .origin                = static_cast<uint8_t>(m.origin),
        .server_kind           = static_cast<uint8_t>(m.serverKind),
        .capture_agent         = m.captureAgent.c_str(),
        .client_version        = m.clientVersion.c_str(),
        .content_id            = m.character.contentId,
        .character_id          = m.character.characterId,
        .character_name        = m.character.name.c_str(),
        .world_name            = m.character.world.c_str(),
        .has_source            = s != nullptr,
        .source_format         = s ? s->format.c_str() : nullptr,
        .source_format_version = s ? s->formatVersion.c_str() : nullptr,
        .skipped_records       = s ? s->skippedRecords : 0,
        .source_metadata       = s ? s->metadata.data() : nullptr,
        .source_metadata_size  = s ? s->metadata.size() : 0,
    };
    std::ranges::copy(m.captureId, out.capture_id);
    std::ranges::copy(m.previousCaptureId, out.previous_capture_id);
    return out;
}

auto fromC(const xicap_metadata& c) -> xicap::Metadata
{
    auto m = xicap::Metadata{
        .origin        = static_cast<xicap::Origin>(c.origin),
        .serverKind    = static_cast<xicap::ServerKind>(c.server_kind),
        .captureAgent  = c.capture_agent,
        .clientVersion = c.client_version,
        .character     = { .contentId = c.content_id, .characterId = c.character_id, .name = c.character_name, .world = c.world_name },
    };
    std::ranges::copy(c.capture_id, m.captureId.begin());
    std::ranges::copy(c.previous_capture_id, m.previousCaptureId.begin());
    if (c.has_source)
    {
        m.source = xicap::Source{
            .format         = c.source_format,
            .formatVersion  = c.source_format_version,
            .skippedRecords = c.skipped_records,
            .metadata       = { c.source_metadata, c.source_metadata + c.source_metadata_size },
        };
    }

    return m;
}

} // namespace

struct xicap_reader
{
    xicap::Reader             reader;
    xicap::Packet             packet;
    std::vector<xicap_marker> markers;
};

struct xicap_writer
{
    xicap::Writer writer;
};

extern "C"
{
    auto xicap_check_header(const uint8_t* const data, const size_t size) -> char*
    {
        return guarded([&]
                       {
                           xicap::checkHeader({ data, size });
                       });
    }

    auto xicap_reader_open(const char* const path, xicap_reader** const out, xicap_info* const info) -> char*
    {
        return guarded([&]
                       {
                           auto* const r = new xicap_reader{ .reader = xicap::Reader(path) };
                           *info         = {
                               .metadata      = toC(r->reader.metadata()),
                               .complete      = r->reader.complete(),
                               .end_timestamp = r->reader.endTimestamp(),
                               .packet_count  = r->reader.packetCount(),
                           };
                           *out = r;
                       });
    }

    auto xicap_reader_next(xicap_reader* const r, xicap_packet* const out, bool* const more) -> char*
    {
        return guarded([&]
                       {
                           *more = r->reader.next(r->packet);
                           if (!*more)
                           {
                               return;
                           }

                           const auto& p = r->packet;
                           r->markers.clear();
                           for (const auto& m : p.markers)
                           {
                               r->markers.push_back({ .kind = static_cast<uint8_t>(m.kind), .text = m.text.data(), .text_size = m.text.size() });
                           }

                           *out = {
                               .timestamp    = p.timestamp,
                               .flags        = p.flags,
                               .channel      = static_cast<uint8_t>(p.channel),
                               .opcode       = p.opcode,
                               .data         = p.data.data(),
                               .size         = p.data.size(),
                               .markers      = r->markers.data(),
                               .marker_count = r->markers.size(),
                           };
                       });
    }

    auto xicap_reader_close(xicap_reader* const r) -> void
    {
        delete r;
    }

    auto xicap_writer_open(const char* const path, const xicap_metadata* const metadata, const bool keep_chat, const bool archive, xicap_writer** const out, uint8_t capture_id[16]) -> char*
    {
        return guarded([&]
                       {
                           const auto  policy = archive ? xicap::FramePolicy::archive() : xicap::FramePolicy::live();
                           const auto  chat   = keep_chat ? xicap::Chat::Keep : xicap::Chat::Redact;
                           auto* const w      = new xicap_writer{ xicap::Writer(path, fromC(*metadata), policy, chat) };
                           std::ranges::copy(w->writer.captureId(), capture_id);
                           *out = w;
                       });
    }

    auto xicap_writer_write(xicap_writer* const w, const xicap_write_packet* const p) -> char*
    {
        return guarded([&]
                       {
                           w->writer.write({
                               .timestamp  = p->timestamp,
                               .direction  = p->client_to_server ? xicap::PacketDirection::ClientToServer : xicap::PacketDirection::ServerToClient,
                               .provenance = p->provenance,
                               .channel    = static_cast<xicap::Channel>(p->channel),
                               .opcode     = p->opcode,
                               .data       = { p->data, p->size },
                           });
                       });
    }

    auto xicap_writer_close(xicap_writer* const w) -> char*
    {
        auto* const err = guarded([&]
                                  {
                                      w->writer.close();
                                  });
        delete w;
        return err;
    }

    auto xicap_transcode(const char* const src, const char* const dst) -> char*
    {
        return guarded([&]
                       {
                           xicap::transcode(src, dst);
                       });
    }
}
