#pragma once

// The reading of a conformance vector as JSON, in the shape
// tests/spec_reader.py produces. Shared by the vector generator and the C++
// conformance test.

#include <xicap/xicap.h>

#include <cstring>
#include <filesystem>
#include <format>
#include <string>
#include <vector>

namespace vectors
{

inline auto errorName(xicap::ErrorCode code) -> std::string
{
    static constexpr const char* names[] = {
        "OpenFailed",
        "BadMagic",
        "UnsupportedVersion",
        "DictionaryMismatch",
        "ShortHeader",
        "ShortExtension",
        "ExtensionTooLarge",
        "CorruptFrame",
        "FrameChecksumMismatch",
        "DecompressFailed",
        "ZstdContextFailed",
        "WriterClosed",
        "AddExtensionAfterPackets",
        "AddMarkerWithoutPacket",
        "PacketTooLarge",
        "CompressFailed",
        "HeaderChecksumMismatch",
        "ExtensionChecksumMismatch",
        "MissingDictionary",
        "MissingPolicy",
        "UnknownFrameKind",
        "UnknownPacketFlag",
        "InvalidPolicy",
        "InvalidExtension",
        "WriteFailed",
        "PacketTooShort",
        "TranscodeRefused",
        "TranscodeMismatch",
    };
    return names[static_cast<size_t>(code)];
}

// Readers that implement only the format, not this library's error codes,
// compare refusals by these classes.
inline auto refusalClass(xicap::ErrorCode code) -> std::string
{
    switch (code)
    {
        case xicap::ErrorCode::BadMagic:
        case xicap::ErrorCode::UnsupportedVersion:
        case xicap::ErrorCode::ShortHeader:
        case xicap::ErrorCode::HeaderChecksumMismatch:
            return "header";
        case xicap::ErrorCode::ShortExtension:
        case xicap::ErrorCode::ExtensionTooLarge:
        case xicap::ErrorCode::ExtensionChecksumMismatch:
        case xicap::ErrorCode::MissingPolicy:
        case xicap::ErrorCode::InvalidPolicy:
        case xicap::ErrorCode::InvalidExtension:
            return "extension";
        case xicap::ErrorCode::MissingDictionary:
        case xicap::ErrorCode::DictionaryMismatch:
            return "dictionary";
        case xicap::ErrorCode::UnknownFrameKind:
        case xicap::ErrorCode::UnknownPacketFlag:
            return "unknown-required";
        default:
            return "frame";
    }
}

template <typename T>
auto hex(const T& bytes) -> std::string
{
    std::string out = "\"";
    for (const auto b : bytes)
    {
        out += std::format("{:02x}", static_cast<unsigned>(b));
    }
    return out + "\"";
}

inline auto str(const std::string& s) -> std::string
{
    std::string out = "\"";
    for (const char c : s)
    {
        if (c == '"' || c == '\\')
        {
            out += '\\';
        }
        if (static_cast<unsigned char>(c) < 0x20)
        {
            out += std::format("\\u{:04x}", static_cast<unsigned>(c));
            continue;
        }
        out += c;
    }
    return out + "\"";
}

template <size_t N>
auto text(const std::array<char, N>& field) -> std::string
{
    return { field.data(), strnlen(field.data(), N) };
}

// Packets and footer facts from one pass in the given mode.
inline auto readPackets(xicap::Reader& reader, std::string& out) -> void
{
    out += "\"packets\": [";
    xicap::ReadPacket p{};
    bool              first = true;
    while (reader.next(p))
    {
        std::string markers;
        for (const auto& m : p.markers)
        {
            markers += std::format("{}[{}, {}]", markers.empty() ? "" : ", ", static_cast<int>(m.kind), str(m.text));
        }
        out += std::format("{}\n    [{}, {}, {}, {}, {}, [{}]]", first ? "" : ",", p.timestamp, p.channel, p.opcode, p.flags, hex(p.data), markers);
        first = false;
    }
    out += "\n  ]";
}

// Everything a normal read sees; throws when the file must be refused.
inline auto normalReading(const std::filesystem::path& path) -> std::string
{
    std::string   out;
    xicap::Reader r(path);
    const auto&   c = r.character();
    out += std::format("  \"result\": \"ok\",\n");
    out += std::format("  \"header\": {{\"version\": \"{}.{}\", \"captureId\": {}, \"previousCaptureId\": {}, \"startTimestamp\": {}, "
                       "\"clockSource\": {}, \"origin\": {}, \"network\": {}, \"startContext\": {}, \"signingKey\": {}, "
                       "\"captureAgent\": {}, \"clientVersion\": {}, \"character\": [{}, {}, {}, {}, {}]}},\n",
                       r.versionMajor(),
                       r.versionMinor(),
                       hex(r.captureId()),
                       hex(r.previousCaptureId()),
                       r.startTimestamp(),
                       static_cast<int>(r.clockSource()),
                       static_cast<int>(r.origin()),
                       static_cast<int>(r.network()),
                       static_cast<int>(r.startContext()),
                       hex(r.signingKey()),
                       str(r.captureAgent()),
                       str(r.clientVersion()),
                       c.contentId,
                       c.characterId,
                       c.worldId,
                       str(text(c.characterName)),
                       str(text(c.worldName)));
    std::string rules;
    for (const auto& rule : r.policy().rules)
    {
        std::string ranges;
        for (const auto& range : rule.ranges)
        {
            ranges += std::format("{}[{}, {}]", ranges.empty() ? "" : ", ", range.offset, range.length);
        }
        rules += std::format("{}[{}, {}, {}, {}, [{}]]", rules.empty() ? "" : ", ", rule.channel, static_cast<int>(rule.direction), static_cast<int>(rule.action), rule.opcode, ranges);
    }
    out += std::format("  \"policy\": [{}, {}, [{}]],\n", str(r.policy().name), r.policy().version, rules);
    if (const auto& s = r.source())
    {
        out += std::format("  \"source\": [{}, {}, {}, {}, {}, {}],\n", str(s->format), str(s->formatVersion), s->skippedRecords, s->utcOffsetSeconds, hex(s->sourceHash), hex(s->metadata));
    }
    else
    {
        out += "  \"source\": null,\n";
    }
    std::string extensions;
    for (const auto& e : r.extensions())
    {
        extensions += std::format("{}[{}, {}]", extensions.empty() ? "" : ", ", e.type, hex(e.data));
    }
    out += std::format("  \"extensions\": [{}],\n", extensions);
    out += std::format("  \"complete\": {},\n  \"footerDamaged\": {},\n  \"endTimestamp\": {},\n  \"totalPacketCount\": {},\n",
                       r.complete(),
                       r.footerDamaged(),
                       r.endTimestamp(),
                       r.totalPacketCount());
    std::string packets;
    readPackets(r, packets);
    out += "  " + packets + ",\n";
    out += std::format("  \"characterMismatch\": {},\n", r.characterMismatch());
    out += std::format("  \"unreadBytes\": {},\n", r.unreadBytes());
    const auto v = r.verify();
    out += std::format("  \"verify\": [{}, {}, {}, {}]", v.signedToEnd, v.verifiedPackets, v.goodCheckpoints, v.firstFailureOffset.has_value());
    if (v.seal)
    {
        out += std::format(",\n  \"seal\": [{}, {}, {}, {}]", hex(v.seal->key), str(v.seal->agent), v.seal->sealedAt, v.seal->good);
    }
    return out;
}

inline auto reading(const std::filesystem::path& path) -> std::string
{
    std::string out = "{\n";
    try
    {
        out += normalReading(path);
    }
    catch (const xicap::Error& e)
    {
        out += std::format("  \"result\": \"{}\",\n  \"refusal\": \"{}\"", errorName(e.code()), refusalClass(e.code()));
    }

    // Recovery mode: how many packets survive, and which regions were skipped.
    try
    {
        xicap::Reader     r(path, { .recovery = true });
        xicap::ReadPacket p{};
        uint64_t          count = 0;
        while (r.next(p))
        {
            count++;
        }
        std::string skipped;
        for (const auto& s : r.skippedRegions())
        {
            skipped += std::format("{}[{}, {}]", skipped.empty() ? "" : ", ", s.offset, s.length);
        }
        out += std::format(",\n  \"recovery\": [{}, [{}]]", count, skipped);
    }
    catch (const xicap::Error& e)
    {
        out += std::format(",\n  \"recovery\": \"{}\"", refusalClass(e.code()));
    }
    return out + "\n}\n";
}

} // namespace vectors
