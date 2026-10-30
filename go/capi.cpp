#include "capi.h"

#include "internal/crc32.h"
#include "xicap/reader.h"
#include "xicap/writer.h"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <exception>

namespace
{

template <size_t N, size_t M>
void copyString(char (&dst)[N], const std::array<char, M>& src)
{
    const auto n = std::min(strnlen(src.data(), M), N - 1);
    std::memcpy(dst, src.data(), n);
    dst[n] = '\0';
}

template <size_t N>
void copyString(char (&dst)[N], const std::string& src)
{
    std::snprintf(dst, N, "%s", src.c_str());
}

template <size_t N>
void copyName(std::array<char, N>& dst, const char* src)
{
    if (src)
    {
        std::snprintf(dst.data(), dst.size(), "%s", src);
    }
}

void setError(char* err, size_t errlen, const char* message)
{
    std::snprintf(err, errlen, "%s", message);
}

template <typename F>
int guarded(char* err, size_t errlen, F&& f)
{
    try
    {
        f();
        return 0;
    }
    catch (const std::exception& e)
    {
        setError(err, errlen, e.what());
        return -1;
    }
}

} // namespace

extern "C" int xicap_check_header(const uint8_t* data, size_t size, char* err, size_t errlen)
{
    xicap::Header header{};
    if (size < sizeof(header))
    {
        setError(err, errlen, "xicap: short header");
        return -1;
    }
    std::memcpy(&header, data, sizeof(header));
    if (header.magic != xicap::MAGIC)
    {
        setError(err, errlen, "xicap: bad magic");
        return -1;
    }
    if (header.versionMajor != xicap::VERSION_MAJOR)
    {
        setError(err, errlen, "xicap: unsupported version");
        return -1;
    }
    if (header.headerSize < xicap::HEADER_SIZE || header.headerSize > xicap::HEADER_SIZE_MAX)
    {
        setError(err, errlen, "xicap: header size out of range");
        return -1;
    }
    if (size < header.headerSize)
    {
        setError(err, errlen, "xicap: short header");
        return -1;
    }
    uint32_t stored = 0;
    std::memcpy(&stored, data + header.headerSize - sizeof(stored), sizeof(stored));
    xicap::internal::Crc32 crc;
    crc.update({ data, header.headerSize - sizeof(stored) });
    if (crc.value() != stored)
    {
        setError(err, errlen, "xicap: header crc mismatch");
        return -1;
    }
    return 0;
}

extern "C" int xicap_read(const char* path, xicap_summary* out, char* err, size_t errlen)
{
    return guarded(err, errlen, [&]
                   {
                       xicap::Reader reader{ path };
                       *out               = {};
                       out->version_major = reader.versionMajor();
                       out->version_minor = reader.versionMinor();
                       copyString(out->capture_agent, reader.captureAgent());
                       copyString(out->client_version, reader.clientVersion());
                       std::ranges::copy(reader.captureId(), out->capture_id);
                       std::ranges::copy(reader.previousCaptureId(), out->previous_capture_id);
                       const auto& character = reader.character();
                       out->content_id       = character.contentId;
                       out->character_id     = character.characterId;
                       out->world_id         = character.worldId;
                       copyString(out->character_name, character.characterName);
                       copyString(out->world_name, character.worldName);
                       out->clock_source    = static_cast<uint8_t>(reader.clockSource());
                       out->origin          = static_cast<uint8_t>(reader.origin());
                       out->network         = static_cast<uint8_t>(reader.network());
                       out->start_context   = static_cast<uint8_t>(reader.startContext());
                       out->start_timestamp = reader.startTimestamp();
                       out->end_timestamp   = out->start_timestamp;
                       copyString(out->policy_name, reader.policy().name);
                       out->policy_version = reader.policy().version;
                       out->rule_count     = static_cast<uint32_t>(reader.policy().rules.size());
                       for (size_t i = 0; i < std::min<size_t>(out->rule_count, XICAP_SUMMARY_RULES); ++i)
                       {
                           const auto& rule = reader.policy().rules[i];
                           out->rules[i]    = {
                               .channel     = rule.channel,
                               .direction   = static_cast<uint8_t>(rule.direction),
                               .action      = static_cast<uint8_t>(rule.action),
                               .opcode      = rule.opcode,
                               .range_count = static_cast<uint16_t>(rule.ranges.size()),
                           };
                       }
                       if (const auto& source = reader.source())
                       {
                           out->has_source = 1;
                           copyString(out->source_format, source->format);
                           copyString(out->source_format_version, source->formatVersion);
                           out->skipped_records = source->skippedRecords;
                       }

                       xicap::ReadPacket packet{};
                       while (reader.next(packet))
                       {
                           out->packets++;
                           out->end_timestamp = packet.timestamp;
                       }
                       if (reader.totalFrames() > 0)
                       {
                           out->start_zone_id = reader.frameZone(0);
                           out->end_zone_id   = reader.frameZone(reader.totalFrames() - 1);
                       }
                       out->frames             = reader.totalFrames();
                       out->complete           = reader.complete() ? 1 : 0;
                       out->footer_damaged     = reader.footerDamaged() ? 1 : 0;
                       out->unread_bytes       = reader.unreadBytes();
                       out->character_mismatch = reader.characterMismatch() ? 1 : 0;

                       const auto verification = reader.verify();
                       std::ranges::copy(verification.key, out->signing_key);
                       out->signed_to_end    = verification.signedToEnd ? 1 : 0;
                       out->verified_packets = verification.verifiedPackets;
                   });
}

struct xicap_writer
{
    xicap::Writer writer;
};

extern "C" xicap_writer* xicap_writer_open(const char* path, const xicap_writer_info* info, char* err, size_t errlen)
{
    xicap_writer* w  = nullptr;
    const int     rc = guarded(err, errlen, [&]
                               {
                               xicap::WriterConfig config{};
                               config.captureAgent          = info->capture_agent ? info->capture_agent : "";
                               config.clientVersion         = info->client_version ? info->client_version : "";
                               config.character.contentId   = info->content_id;
                               config.character.characterId = info->character_id;
                               config.character.worldId     = info->world_id;
                               copyName(config.character.characterName, info->character_name);
                               copyName(config.character.worldName, info->world_name);
                               config.clockSource  = static_cast<xicap::ClockSource>(info->clock_source);
                               config.origin       = static_cast<xicap::Origin>(info->origin);
                               config.network      = static_cast<xicap::Network>(info->network);
                               config.startContext = static_cast<xicap::StartContext>(info->start_context);
                               std::ranges::copy(info->previous_capture_id, config.previousCaptureId.begin());
                               std::ranges::copy(info->signing_seed, config.signingSeed.begin());
                               if (info->has_source)
                               {
                                   xicap::SourceInfo source{};
                                   source.format           = info->source_format ? info->source_format : "";
                                   source.formatVersion    = info->source_format_version ? info->source_format_version : "";
                                   source.skippedRecords   = info->skipped_records;
                                   source.utcOffsetSeconds = info->utc_offset_seconds;
                                   std::ranges::copy(info->source_hash, source.sourceHash.begin());
                                   if (info->metadata_size > 0)
                                   {
                                       source.metadata.assign(info->metadata, info->metadata + info->metadata_size);
                                   }
                                   config.source = std::move(source);
                               }
                               if (info->has_policy)
                               {
                                   xicap::ExclusionPolicy p{ .name = info->policy_name ? info->policy_name : "", .version = info->policy_version, .rules = {} };
                                   size_t                 next = 0;
                                   for (size_t i = 0; i < info->rule_count; ++i)
                                   {
                                       const auto&          r = info->rules[i];
                                       xicap::ExclusionRule rule{ .channel = r.channel, .direction = static_cast<xicap::ExclusionDirection>(r.direction), .action = static_cast<xicap::ExclusionAction>(r.action), .opcode = r.opcode, .ranges = {} };
                                       for (uint16_t j = 0; j < r.range_count; ++j)
                                       {
                                           if (next >= info->range_count)
                                           {
                                               throw xicap::Error(xicap::ErrorCode::InvalidPolicy, "xicap: rules ask for more ranges than given");
                                           }
                                           rule.ranges.push_back({ info->ranges[next].offset, info->ranges[next].length });
                                           next++;
                                       }
                                       p.rules.push_back(std::move(rule));
                                   }
                                   config.policy = std::move(p);
                               }
                               xicap::FramePolicy policy{};
                               if (!info->dictionary)
                               {
                                   policy.dictionary = {};
                               }
                               w = new xicap_writer{ xicap::Writer{ path, std::move(config), policy } };
                               });
    return rc == 0 ? w : nullptr;
}

extern "C" int xicap_writer_add_extension(xicap_writer* w, uint32_t type, const uint8_t* data, size_t size, char* err, size_t errlen)
{
    return guarded(err, errlen, [&]
                   {
                       w->writer.addExtension(type, std::span{ reinterpret_cast<const std::byte*>(data), size });
                   });
}

extern "C" int xicap_writer_write(xicap_writer* w, uint64_t timestamp, int client_to_server, uint8_t channel, uint16_t opcode, uint16_t provenance, const uint8_t* data, size_t size, char* err, size_t errlen)
{
    return guarded(err, errlen, [&]
                   {
                       w->writer.write({
                           .timestamp  = timestamp,
                           .direction  = client_to_server ? xicap::PacketDirection::ClientToServer : xicap::PacketDirection::ServerToClient,
                           .data       = std::span{ reinterpret_cast<const std::byte*>(data), size },
                           .channel    = channel,
                           .opcode     = opcode,
                           .provenance = provenance,
                       });
                   });
}

extern "C" int xicap_writer_mark(xicap_writer* w, uint8_t kind, const char* text, char* err, size_t errlen)
{
    return guarded(err, errlen, [&]
                   {
                       w->writer.mark(static_cast<xicap::MarkerKind>(kind), text ? text : "");
                   });
}

extern "C" int xicap_writer_flush(xicap_writer* w, char* err, size_t errlen)
{
    return guarded(err, errlen, [&]
                   {
                       w->writer.flush();
                   });
}

extern "C" void xicap_writer_ids(const xicap_writer* w, uint8_t capture_id[16], uint8_t public_key[32])
{
    std::ranges::copy(w->writer.captureId(), capture_id);
    std::ranges::copy(w->writer.publicKey(), public_key);
}

extern "C" int xicap_writer_close(xicap_writer* w, char* err, size_t errlen)
{
    const int rc = guarded(err, errlen, [&]
                           {
                               w->writer.close();
                           });
    delete w;
    return rc;
}
