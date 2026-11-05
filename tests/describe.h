#pragma once

#include <xicap/xicap.h>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <format>
#include <span>
#include <string>

namespace test
{

template <typename Bytes>
auto hex(const Bytes& bytes) -> std::string
{
    std::string out;
    for (const auto b : bytes)
    {
        out += std::format("{:02x}", static_cast<uint8_t>(b));
    }

    return out;
}

inline auto describe(const xicap::Metadata& m) -> nlohmann::ordered_json
{
    nlohmann::ordered_json source;
    if (m.source)
    {
        source = { { "format", m.source->format }, { "formatVersion", m.source->formatVersion }, { "skippedRecords", m.source->skippedRecords }, { "metadata", hex(m.source->metadata) } };
    }

    return {
        { "captureId", hex(m.captureId) },
        { "previousCaptureId", hex(m.previousCaptureId) },
        { "startTimestamp", m.startTimestamp },
        { "origin", m.origin },
        { "serverKind", m.serverKind },
        { "captureAgent", m.captureAgent },
        { "clientVersion", m.clientVersion },
        { "character", { { "contentId", m.character.contentId }, { "characterId", m.character.characterId }, { "name", m.character.name }, { "world", m.character.world } } },
        { "source", source },
    };
}

inline auto describe(const std::filesystem::path& path) -> nlohmann::ordered_json
{
    try
    {
        xicap::Reader r(path);
        auto          packets = nlohmann::ordered_json::array();
        for (const auto& p : r)
        {
            auto markers = nlohmann::ordered_json::array();
            for (const auto& m : p.markers)
            {
                markers.push_back({ { "kind", m.kind }, { "text", hex(m.text) } });
            }

            packets.push_back({ { "timestamp", p.timestamp }, { "flags", p.flags }, { "channel", p.channel }, { "opcode", p.opcode }, { "data", hex(p.data) }, { "markers", markers } });
        }

        return {
            { "refused", false },
            { "complete", r.complete() },
            { "endTimestamp", r.endTimestamp() },
            { "packetCount", r.packetCount() },
            { "metadata", describe(r.metadata()) },
            { "packets", packets },
        };
    }
    catch (const xicap::Error&)
    {
        return { { "refused", true } };
    }
}

} // namespace test
