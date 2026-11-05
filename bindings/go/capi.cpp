#include "capi.h"

#include "metadata/codec.h"
#include "xicap/xicap.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <ranges>
#include <span>
#include <string>
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

template <size_t N>
auto copyText(char (&dst)[N], const std::string& src) -> void
{
    const auto n = std::min(src.size(), N - 1);
    std::memcpy(dst, src.data(), n);
    dst[n] = '\0';
}

// A copy the C side owns and frees.
template <std::ranges::contiguous_range R>
auto copyOut(const R& src) -> std::ranges::range_value_t<R>*
{
    using T   = std::ranges::range_value_t<R>;
    auto* out = static_cast<T*>(std::malloc(std::ranges::size(src) * sizeof(T)));
    std::ranges::copy(src, out);
    return out;
}

auto summarize(const char* path, xicap_summary& s) -> void
{
    xicap::Reader r(path);
    const auto&   m = r.metadata();
    std::ranges::copy(m.captureId, s.capture_id);
    std::ranges::copy(m.previousCaptureId, s.previous_capture_id);
    s.start_timestamp = m.startTimestamp;
    s.origin          = static_cast<uint8_t>(m.origin);
    s.server_kind     = static_cast<uint8_t>(m.serverKind);
    copyText(s.capture_agent, m.captureAgent);
    copyText(s.client_version, m.clientVersion);
    s.content_id   = m.character.contentId;
    s.character_id = m.character.characterId;
    copyText(s.character_name, m.character.name);
    copyText(s.world_name, m.character.world);
    copyText(s.policy_name, m.policy.name);
    s.policy_version = m.policy.version;
    s.policy_rules   = static_cast<uint32_t>(m.policy.rules.size());
    if (m.source)
    {
        s.has_source = true;
        copyText(s.source_format, m.source->format);
        copyText(s.source_format_version, m.source->formatVersion);
        s.skipped_records      = m.source->skippedRecords;
        s.source_metadata      = copyOut(m.source->metadata);
        s.source_metadata_size = m.source->metadata.size();
    }

    std::vector<xicap_marker> markers;
    for (const auto& p : r)
    {
        s.channels[p.channel] = true;
        for (const auto& marker : p.markers)
        {
            markers.push_back({ static_cast<uint8_t>(marker.kind), copyOut(marker.text), marker.text.size(), s.packets_read, p.timestamp });
        }

        s.last_timestamp = p.timestamp;
        s.packets_read++;
    }

    s.complete      = r.complete();
    s.end_timestamp = r.endTimestamp();
    s.packet_count  = r.packetCount();
    s.markers       = copyOut(markers);
    s.marker_count  = markers.size();
}

} // namespace

struct xicap_writer
{
    xicap::Writer writer;
};

extern "C"
{
    auto xicap_check_header(const uint8_t* data, size_t size) -> char*
    {
        return guarded([&]
                       {
                           xicap::Metadata m;
                           xicap::metadata::readHeader({ data, size }, m);
                       });
    }

    auto xicap_read(const char* path, xicap_summary* out) -> char*
    {
        *out            = {};
        auto* const err = guarded([&]
                                  {
                                      summarize(path, *out);
                                  });
        if (err != nullptr)
        {
            xicap_free_summary(out);
        }

        return err;
    }

    auto xicap_free_summary(xicap_summary* s) -> void
    {
        for (const auto& m : std::span{ s->markers, s->marker_count })
        {
            std::free(m.text);
        }

        std::free(s->markers);
        std::free(s->source_metadata);
    }

    auto xicap_writer_open(const char* path, const xicap_writer_info* info, xicap_writer** out) -> char*
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
                           if (info->keep_chat)
                           {
                               m.policy = {};
                           }

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
                           *out              = new xicap_writer{ xicap::Writer(path, std::move(m), policy) };
                       });
    }

    auto xicap_writer_write(xicap_writer* w, uint64_t timestamp, bool client_to_server, uint8_t channel, uint16_t opcode, uint16_t provenance, const uint8_t* data, size_t size) -> char*
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

    auto xicap_writer_close(xicap_writer* w) -> char*
    {
        auto* const err = guarded([&]
                                  {
                                      w->writer.close();
                                  });
        delete w;
        return err;
    }

    auto xicap_transcode(const char* src, const char* dst) -> char*
    {
        return guarded([&]
                       {
                           xicap::transcode(src, dst);
                       });
    }
}
