#include "capi.h"

#include "internal/decoder.h"
#include "xicap/reader.h"
#include "xicap/transcode.h"
#include "xicap/writer.h"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <exception>
#include <stdexcept>

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

extern "C" int xicap_header_size(const uint8_t* data, size_t size)
{
    const auto version = size > offsetof(xicap::Header, versionMajor) ? data[offsetof(xicap::Header, versionMajor)] : 0;
    if (size < offsetof(xicap::Header, extensionCount) || !std::equal(xicap::MAGIC.begin(), xicap::MAGIC.end(), data) ||
        (version != 3 && version != xicap::VERSION_MAJOR))
    {
        return -1;
    }
    uint16_t headerSize = 0;
    std::memcpy(&headerSize, data + offsetof(xicap::Header, headerSize), sizeof(headerSize));
    return headerSize >= xicap::HEADER_SIZE && headerSize <= xicap::HEADER_SIZE_MAX ? headerSize : -1;
}

extern "C" int xicap_check_header(const uint8_t* data, size_t size, char* err, size_t errlen)
{
    return guarded(err, errlen, [&]
                   {
                       const std::span<const uint8_t> bytes{ data, size };
                       const auto                     length = xicap::internal::headerSize(bytes);
                       if (size < length)
                       {
                           throw xicap::Error(xicap::ErrorCode::ShortHeader, "xicap: short header");
                       }
                       xicap::internal::Start start;
                       xicap::internal::readHeader(bytes.first(length), start);
                   });
}

extern "C" int xicap_markers(const char* path, xicap_marker** out, size_t* count, char* err, size_t errlen)
{
    *out   = nullptr;
    *count = 0;
    std::vector<xicap_marker> markers;
    const auto                rc = guarded(err, errlen, [&]
                                           {
                                xicap::Reader     reader{ path };
                                xicap::ReadPacket packet{};
                                for (uint64_t index = 0; reader.next(packet); ++index)
                                {
                                    for (const auto& m : packet.markers)
                                    {
                                        auto* text = static_cast<char*>(std::malloc(m.text.size() + 1));
                                        if (text == nullptr)
                                        {
                                            throw std::bad_alloc();
                                        }
                                        std::memcpy(text, m.text.c_str(), m.text.size() + 1);
                                        markers.push_back({ .kind = static_cast<uint8_t>(m.kind), .text = text, .packet = index, .timestamp = packet.timestamp });
                                    }
                                }
                                           });
    if (rc != 0 || markers.empty())
    {
        xicap_free_markers(markers.data(), markers.size());
        return rc;
    }
    *out = static_cast<xicap_marker*>(std::malloc(markers.size() * sizeof(xicap_marker)));
    if (*out == nullptr)
    {
        xicap_free_markers(markers.data(), markers.size());
        setError(err, errlen, "xicap: out of memory");
        return -1;
    }
    std::memcpy(*out, markers.data(), markers.size() * sizeof(xicap_marker));
    *count = markers.size();
    return 0;
}

extern "C" void xicap_free_markers(xicap_marker* markers, size_t count)
{
    for (size_t i = 0; i < count; ++i)
    {
        std::free(markers[i].text);
    }
}

extern "C" uint8_t xicap_policy_action(const xicap_rule* rules, size_t rule_count, uint8_t channel, uint8_t direction, uint16_t opcode)
{
    xicap::ExclusionPolicy policy;
    for (size_t i = 0; i < rule_count; ++i)
    {
        policy.rules.push_back({ .channel = rules[i].channel, .direction = static_cast<xicap::ExclusionDirection>(rules[i].direction), .action = static_cast<xicap::ExclusionAction>(rules[i].action), .opcode = rules[i].opcode, .ranges = {} });
    }
    const auto* rule = xicap::ruleFor(policy, channel, static_cast<xicap::PacketDirection>(direction), opcode);
    return rule == nullptr ? 0 : static_cast<uint8_t>(rule->action);
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
                       out->first_failure    = verification.firstFailureOffset.value_or(0);
                       if (const auto& seal = verification.seal)
                       {
                           out->sealed    = 1;
                           out->seal_ok   = seal->good ? 1 : 0;
                           out->sealed_at = seal->sealedAt;
                           std::ranges::copy(seal->key, out->seal_key);
                           copyString(out->seal_agent, seal->agent);
                       }
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
                                   if (next != info->range_count)
                                   {
                                       throw xicap::Error(xicap::ErrorCode::InvalidPolicy, "xicap: rules take fewer ranges than given");
                                   }
                                   config.policy = std::move(p);
                               }
                               auto policy = info->preset == 1 ? xicap::FramePolicy::archive() : xicap::FramePolicy::live();
                               // Another level takes its own match table: the live one suits level 7.
                               if (info->level != 0 && info->level != policy.compressionLevel)
                               {
                                   policy.compressionLevel = info->level;
                                   policy.hashLog          = 0;
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

extern "C" int xicap_cut(const char* src, const char* dst, uint64_t first, uint64_t last, const char* capture_agent, const uint8_t signing_seed[32], const uint8_t source_hash[64], const uint8_t* metadata, size_t metadata_size, char* err, size_t errlen)
{
    return guarded(err, errlen, [&]
                   {
                       xicap::CutOptions options{ .first = first, .last = last, .seed = {}, .agent = capture_agent ? capture_agent : "", .sourceHash = {}, .metadata = {} };
                       std::copy_n(signing_seed, options.seed.size(), options.seed.begin());
                       std::copy_n(source_hash, options.sourceHash.size(), options.sourceHash.begin());
                       if (metadata_size > 0)
                       {
                           options.metadata.assign(metadata, metadata + metadata_size);
                       }
                       xicap::cut(src, dst, options);
                   });
}

extern "C" int xicap_transcode(const char* src, const char* dst, const xicap_transcode_info* info, char* err, size_t errlen)
{
    return guarded(err, errlen, [&]
                   {
                       xicap::TranscodeOptions options{
                           .policy     = xicap::FramePolicy::archive(),
                           .signing    = info->seal ? xicap::Signing::Seal : xicap::Signing::Resign,
                           .seed       = {},
                           .agent      = info->agent ? info->agent : "",
                           .sourceHash = {},
                           .metadata   = {},
                       };
                       if (info->level != 0)
                       {
                           options.policy.compressionLevel = info->level;
                       }
                       std::ranges::copy(info->seed, options.seed.begin());
                       std::ranges::copy(info->source_hash, options.sourceHash.begin());
                       if (info->metadata_size > 0)
                       {
                           options.metadata.assign(info->metadata, info->metadata + info->metadata_size);
                       }
                       xicap::transcode(src, dst, options);
                   });
}
