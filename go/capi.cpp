#include "capi.h"

#include "metadata_codec.h"
#include "xicap/xicap.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <span>
#include <string>
#include <vector>

namespace
{

template <size_t N>
auto copyText(char (&dst)[N], const std::string& src) -> void
{
    const auto n = std::min(src.size(), N - 1);
    std::memcpy(dst, src.data(), n);
    dst[n] = '\0';
}

auto text(const char* s) -> std::string
{
    if (s == nullptr)
    {
        return {};
    }
    return s;
}

template <typename F>
auto guarded(char* err, size_t errlen, F&& f) -> int
{
    try
    {
        f();
        return 0;
    }
    catch (const std::exception& e)
    {
        std::snprintf(err, errlen, "%s", e.what());
        return -1;
    }
}

auto summarize(const char* path, xicap_summary& s) -> void
{
    xicap::Reader r(path);
    const auto&   m = r.metadata();
    std::ranges::copy(m.captureId, s.capture_id);
    std::ranges::copy(m.previousCaptureId, s.previous_capture_id);
    s.start_timestamp = m.startTimestamp;
    s.origin          = static_cast<uint8_t>(m.origin);
    s.network         = static_cast<uint8_t>(m.network);
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
        s.has_source = 1;
        copyText(s.source_format, m.source->format);
        copyText(s.source_format_version, m.source->formatVersion);
        s.skipped_records      = m.source->skippedRecords;
        s.source_metadata      = static_cast<uint8_t*>(std::malloc(m.source->metadata.size() + 1));
        s.source_metadata_size = m.source->metadata.size();
        std::ranges::copy(m.source->metadata, s.source_metadata);
    }

    std::vector<xicap_marker> markers;
    for (const auto& p : r)
    {
        s.channels[p.channel / 8] |= static_cast<uint8_t>(1U << (p.channel % 8));
        for (const auto& marker : p.markers)
        {
            auto* t = static_cast<char*>(std::malloc(marker.text.size() + 1));
            std::memcpy(t, marker.text.data(), marker.text.size());
            markers.push_back({ static_cast<uint8_t>(marker.kind), t, marker.text.size(), s.packets, p.timestamp });
        }
        s.end_timestamp = p.timestamp;
        s.packets++;
    }
    s.complete     = r.complete();
    s.markers      = static_cast<xicap_marker*>(std::malloc(markers.size() * sizeof(xicap_marker) + 1));
    s.marker_count = markers.size();
    std::ranges::copy(markers, s.markers);
}

} // namespace

struct xicap_writer
{
    xicap::Writer writer;
};

extern "C"
{
    int xicap_check_header(const uint8_t* data, size_t size, char* err, size_t errlen)
    {
        return guarded(err, errlen, [&]
                       {
                           if (size < sizeof(xicap::format::Header))
                           {
                               throw xicap::Error("xicap: short header");
                           }
                           xicap::Metadata m;
                           xicap::internal::readHeader({ data, size }, m);
                       });
    }

    int xicap_read(const char* path, xicap_summary* out, char* err, size_t errlen)
    {
        *out = {};
        return guarded(err, errlen, [&]
                       {
                           try
                           {
                               summarize(path, *out);
                           }
                           catch (...)
                           {
                               xicap_free_summary(out);
                               throw;
                           }
                       });
    }

    void xicap_free_summary(xicap_summary* s)
    {
        for (size_t i = 0; i < s->marker_count; ++i)
        {
            std::free(s->markers[i].text);
        }
        std::free(s->markers);
        std::free(s->source_metadata);
        s->markers         = nullptr;
        s->marker_count    = 0;
        s->source_metadata = nullptr;
    }

    xicap_writer* xicap_writer_open(const char* path, const xicap_writer_info* info, char* err, size_t errlen)
    {
        xicap_writer* w = nullptr;
        guarded(err, errlen, [&]
                {
                    auto m = xicap::Metadata{
                        .origin        = static_cast<xicap::Origin>(info->origin),
                        .network       = static_cast<xicap::Network>(info->network),
                        .captureAgent  = text(info->capture_agent),
                        .clientVersion = text(info->client_version),
                        .character     = { .contentId = info->content_id, .characterId = info->character_id, .name = text(info->character_name), .world = text(info->world_name) },
                    };
                    if (info->keep_chat != 0)
                    {
                        m.policy = {};
                    }
                    if (info->has_source != 0)
                    {
                        m.source = xicap::Source{
                            .format         = text(info->source_format),
                            .formatVersion  = text(info->source_format_version),
                            .skippedRecords = info->skipped_records,
                            .metadata       = { info->source_metadata, info->source_metadata + info->source_metadata_size },
                        };
                    }
                    auto policy = xicap::FramePolicy::live();
                    if (info->archive != 0)
                    {
                        policy = xicap::FramePolicy::archive();
                    }
                    w = new xicap_writer{ xicap::Writer(path, std::move(m), policy) };
                });
        return w;
    }

    int xicap_writer_write(xicap_writer* w, uint64_t timestamp, int client_to_server, uint8_t channel, uint16_t opcode, uint16_t provenance, const uint8_t* data, size_t size, char* err, size_t errlen)
    {
        return guarded(err, errlen, [&]
                       {
                           w->writer.write({
                               .timestamp  = timestamp,
                               .direction  = static_cast<xicap::PacketDirection>(client_to_server != 0),
                               .data       = std::as_bytes(std::span{ data, size }),
                               .channel    = channel,
                               .opcode     = opcode,
                               .provenance = provenance,
                           });
                       });
    }

    int xicap_writer_close(xicap_writer* w, char* err, size_t errlen)
    {
        const auto rc = guarded(err, errlen, [&]
                                {
                                    w->writer.close();
                                });
        delete w;
        return rc;
    }

    int xicap_transcode(const char* src, const char* dst, char* err, size_t errlen)
    {
        return guarded(err, errlen, [&]
                       {
                           xicap::transcode(src, dst);
                       });
    }
}
