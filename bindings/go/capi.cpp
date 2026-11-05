#include "capi.h"

#include "metadata/codec.h"
#include "xicap/xicap.h"

#include <cstdlib>
#include <cstring>
#include <exception>
#include <span>
#include <vector>

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
                           xicap::Metadata m;
                           xicap::metadata::readHeader({ data, size }, m);
                       });
    }

    auto xicap_reader_open(const char* const path, xicap_reader** const out, xicap_info* const info) -> char*
    {
        return guarded([&]
                       {
                           auto* const r = new xicap_reader{ .reader = xicap::Reader(path) };
                           const auto& m = r->reader.metadata();
                           const auto* s = m.source ? &*m.source : nullptr;
                           *info         = {
                               .capture_id            = m.captureId.data(),
                               .previous_capture_id   = m.previousCaptureId.data(),
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
                               .complete              = r->reader.complete(),
                               .end_timestamp         = r->reader.endTimestamp(),
                               .packet_count          = r->reader.packetCount(),
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
                               .channel      = p.channel,
                               .opcode       = p.opcode,
                               .data         = reinterpret_cast<const uint8_t*>(p.data.data()),
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

    auto xicap_writer_open(const char* const path, const xicap_writer_info* const info, xicap_writer** const out) -> char*
    {
        return guarded([&]
                       {
                           auto m = xicap::Metadata{
                               .origin        = static_cast<xicap::Origin>(info->origin),
                               .serverKind    = static_cast<xicap::ServerKind>(info->server_kind),
                               .captureAgent  = info->capture_agent,
                               .clientVersion = info->client_version,
                               .character     = { .contentId = info->content_id, .characterId = info->character_id, .name = info->character_name, .world = info->world_name },
                           };
                           if (info->has_source)
                           {
                               m.source = xicap::Source{
                                   .format         = info->source_format,
                                   .formatVersion  = info->source_format_version,
                                   .skippedRecords = info->skipped_records,
                                   .metadata       = { info->source_metadata, info->source_metadata + info->source_metadata_size },
                               };
                           }

                           const auto policy = info->archive ? xicap::FramePolicy::archive() : xicap::FramePolicy::live();
                           const auto chat   = info->keep_chat ? xicap::Chat::Keep : xicap::Chat::Redact;
                           *out              = new xicap_writer{ xicap::Writer(path, std::move(m), policy, chat) };
                       });
    }

    auto xicap_writer_write(xicap_writer* const w, const uint64_t timestamp, const bool client_to_server, const uint8_t channel, const uint16_t opcode, const uint16_t provenance, const uint8_t* const data, const size_t size) -> char*
    {
        return guarded([&]
                       {
                           w->writer.write({
                               .timestamp  = timestamp,
                               .direction  = client_to_server ? xicap::PacketDirection::ClientToServer : xicap::PacketDirection::ServerToClient,
                               .data       = std::as_bytes(std::span{ data, size }),
                               .channel    = channel,
                               .opcode     = opcode,
                               .provenance = provenance,
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
