// Prints what a capture holds: header, provenance, signatures, zones, and
// packet statistics, with optional hex dumps.

#include <xicap/xicap.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace
{

auto formatTimestamp(uint64_t ms) -> std::string
{
    const auto tp = std::chrono::sys_time<std::chrono::milliseconds>{ std::chrono::milliseconds{ ms } };
    return std::format("{:%Y-%m-%d %H:%M:%S} UTC", tp);
}

auto formatDuration(const uint64_t ms) -> std::string
{
    const uint64_t seconds = ms / 1000;
    const uint64_t minutes = seconds / 60;
    const uint64_t hours   = minutes / 60;

    std::ostringstream oss;
    if (hours > 0)
    {
        oss << hours << "h ";
    }
    if (minutes > 0 || hours > 0)
    {
        oss << (minutes % 60) << "m ";
    }
    oss << (seconds % 60) << "s";
    return oss.str();
}

auto formatBytes(uint64_t bytes) -> std::string
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    if (bytes >= 1024 * 1024 * 1024)
    {
        oss << (static_cast<double>(bytes) / (1024 * 1024 * 1024)) << " GB";
    }
    else if (bytes >= 1024 * 1024)
    {
        oss << (static_cast<double>(bytes) / (1024 * 1024)) << " MB";
    }
    else if (bytes >= 1024)
    {
        oss << (static_cast<double>(bytes) / 1024) << " KB";
    }
    else
    {
        oss << bytes << " B";
    }
    return oss.str();
}

template <typename T>
auto hex(const T& bytes) -> std::string
{
    std::string out;
    for (const auto b : bytes)
    {
        out += std::format("{:02x}", static_cast<unsigned>(b));
    }
    return out;
}

auto hexDump(std::span<const std::byte> data, size_t maxBytes = 64) -> void
{
    const size_t len = std::min(data.size(), maxBytes);
    for (size_t i = 0; i < len; ++i)
    {
        if (i > 0 && i % 16 == 0)
        {
            std::cout << "\n         ";
        }
        std::cout << std::format("{:02x} ", static_cast<unsigned>(data[i]));
    }
    if (data.size() > maxBytes)
    {
        std::cout << "... (" << (data.size() - maxBytes) << " more bytes)";
    }
    std::cout << "\n";
}

template <size_t N>
auto text(const std::array<char, N>& field) -> std::string
{
    return { field.data(), strnlen(field.data(), N) };
}

auto name(xicap::Network n) -> const char*
{
    switch (n)
    {
        case xicap::Network::Retail:
            return "retail";
        case xicap::Network::Private:
            return "private server";
        default:
            return "unknown";
    }
}

auto name(xicap::StartContext s) -> const char*
{
    switch (s)
    {
        case xicap::StartContext::Login:
            return "at a login";
        case xicap::StartContext::MidSession:
            return "mid-session";
        default:
            return "unknown";
    }
}

auto name(xicap::Origin o) -> const char*
{
    switch (o)
    {
        case xicap::Origin::Live:
            return "recorded live";
        case xicap::Origin::Converted:
            return "converted";
        default:
            return "unknown";
    }
}

auto name(xicap::MarkerKind k) -> const char*
{
    switch (k)
    {
        case xicap::MarkerKind::Login:
            return "login";
        case xicap::MarkerKind::Logout:
            return "logout";
        default:
            return "note";
    }
}

} // namespace

int main(int argc, char* argv[])
{
    bool        dumpPackets = false;
    bool        recovery    = false;
    uint64_t    limit       = 0;
    std::string filename;

    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--dump")
        {
            dumpPackets = true;
        }
        else if (arg == "--recovery")
        {
            recovery = true;
        }
        else if (arg == "--limit" && i + 1 < argc)
        {
            limit = std::stoull(argv[++i]);
        }
        else if (arg[0] != '-')
        {
            filename = arg;
        }
    }

    if (filename.empty())
    {
        std::cerr << "Usage: " << argv[0] << " [--dump] [--limit N] [--recovery] <file.xicap>\n";
        std::cerr << "  --dump      Show packet hex dumps\n";
        std::cerr << "  --limit N   Only dump the first N packets\n";
        std::cerr << "  --recovery  Skip damaged frames instead of stopping\n";
        return 1;
    }

    try
    {
        const auto    fileSize = std::filesystem::file_size(filename);
        xicap::Reader reader(filename, { .recovery = recovery });

        std::cout << "=== " << filename << " (" << formatBytes(fileSize) << ") ===\n";
        std::cout << "Version:        " << static_cast<int>(reader.versionMajor()) << "." << static_cast<int>(reader.versionMinor()) << "\n";
        std::cout << "Capture id:     " << hex(reader.captureId()) << "\n";
        if (std::ranges::any_of(reader.previousCaptureId(), [](uint8_t b)
                                {
                                    return b != 0;
                                }))
        {
            std::cout << "Continues:      " << hex(reader.previousCaptureId()) << "\n";
        }
        std::cout << "Recorder:       " << reader.captureAgent() << "\n";
        std::cout << "Client:         " << reader.clientVersion() << "\n";
        std::cout << "Origin:         " << name(reader.origin()) << ", " << name(reader.network()) << ", starts " << name(reader.startContext()) << "\n";

        const auto& character = reader.character();
        std::cout << "Character:      " << text(character.characterName) << " (" << text(character.worldName) << ")\n";
        std::cout << "Content id:     " << character.contentId << ", world " << character.worldId << "\n";
        std::cout << "Start:          " << formatTimestamp(reader.startTimestamp()) << "\n";
        std::cout << "Duration:       " << formatDuration(reader.durationMs()) << "\n";
        std::cout << "Frames:         " << reader.totalFrames() << (reader.complete() ? "" : " (cut off, no footer)") << "\n";
        if (reader.footerDamaged())
        {
            std::cout << "Footer:         damaged\n";
        }
        const auto& policy = reader.policy();
        std::cout << "Policy:         " << policy.name << " v" << policy.version << ", " << policy.rules.size() << " rules\n";
        if (const auto& source = reader.source())
        {
            std::cout << "Source:         " << source->format << " " << source->formatVersion << ", " << source->skippedRecords << " records skipped\n";
        }
        for (const auto& ext : reader.extensions())
        {
            std::cout << "Extension:      " << std::format("{:#x}", ext.type) << ", " << formatBytes(ext.data.size()) << "\n";
        }

        const auto verification = reader.verify();
        std::cout << "Signed by:      " << hex(verification.key) << "\n";
        std::cout << "Signatures:     "
                  << (verification.signedToEnd ? "signed to the end" : std::format("{} packets verified, {} checkpoints", verification.verifiedPackets, verification.goodCheckpoints));
        if (verification.firstFailureOffset)
        {
            std::cout << ", FAILED at offset " << *verification.firstFailureOffset;
        }
        std::cout << "\n";

        const auto zones = reader.listZones();
        if (!zones.empty())
        {
            std::cout << "\n=== Zones Visited ===\n";
            for (const auto& zone : zones)
            {
                std::cout << "  Zone " << zone.zoneId << " at " << formatTimestamp(zone.timestamp) << "\n";
            }
        }

        std::map<uint16_t, uint64_t> incomingOpcodes;
        std::map<uint16_t, uint64_t> outgoingOpcodes;
        std::map<uint16_t, uint64_t> incomingBytes;
        std::map<uint16_t, uint64_t> outgoingBytes;
        std::map<uint8_t, uint64_t>  channels;
        uint64_t                     totalIncoming      = 0;
        uint64_t                     totalOutgoing      = 0;
        uint64_t                     totalIncomingBytes = 0;
        uint64_t                     totalOutgoingBytes = 0;
        uint64_t                     excluded           = 0;
        uint64_t                     packetCount        = 0;

        for (const auto& packet : reader)
        {
            const auto size = packet.data.size();
            channels[packet.channel]++;
            if (packet.flags & xicap::PacketFlag::Excluded)
            {
                excluded++;
            }
            if (packet.channel == static_cast<uint8_t>(xicap::Channel::Game))
            {
                const bool in = packet.direction == xicap::PacketDirection::ServerToClient;
                (in ? incomingOpcodes : outgoingOpcodes)[packet.opcode]++;
                (in ? incomingBytes : outgoingBytes)[packet.opcode] += size;
                (in ? totalIncoming : totalOutgoing)++;
                (in ? totalIncomingBytes : totalOutgoingBytes) += size;
            }

            if (dumpPackets && (limit == 0 || packetCount < limit))
            {
                for (const auto& marker : packet.markers)
                {
                    std::cout << "  -- " << name(marker.kind) << (marker.text.empty() ? "" : ": " + marker.text) << "\n";
                }
                std::cout << "[" << formatTimestamp(packet.timestamp) << "] ch" << static_cast<int>(packet.channel) << " "
                          << (packet.direction == xicap::PacketDirection::ServerToClient ? "S2C" : "C2S")
                          << std::format(" 0x{:03x} flags {:#06x}", packet.opcode, packet.flags) << " (" << size << " bytes)\n";
                std::cout << "         ";
                hexDump(packet.data);
            }
            packetCount++;
        }

        std::cout << "\n=== Packet Summary ===\n";
        std::cout << "Total Packets:  " << packetCount << " (" << excluded << " stubbed)\n";
        for (const auto& [channel, count] : channels)
        {
            std::cout << "Channel " << static_cast<int>(channel) << ":      " << count << " packets\n";
        }
        std::cout << "Game S2C:       " << totalIncoming << " packets, " << formatBytes(totalIncomingBytes) << "\n";
        std::cout << "Game C2S:       " << totalOutgoing << " packets, " << formatBytes(totalOutgoingBytes) << "\n";
        const uint64_t raw = totalIncomingBytes + totalOutgoingBytes;
        std::cout << "Ratio:          " << std::fixed << std::setprecision(2) << (fileSize > 0 ? static_cast<double>(raw) / fileSize : 0.0) << "x\n";

        const auto top = [](const char* title, const std::map<uint16_t, uint64_t>& counts, std::map<uint16_t, uint64_t>& bytes)
        {
            std::cout << "\n=== Top " << title << " Opcodes (by count) ===\n";
            std::vector<std::pair<uint16_t, uint64_t>> sorted(counts.begin(), counts.end());
            std::ranges::sort(sorted, [](const auto& a, const auto& b)
                              {
                                  return a.second > b.second;
                              });
            for (size_t i = 0; i < std::min<size_t>(10, sorted.size()); ++i)
            {
                std::cout << std::format("  0x{:03x}: ", sorted[i].first) << sorted[i].second << " pkts, " << formatBytes(bytes[sorted[i].first]) << "\n";
            }
        };
        top("Incoming", incomingOpcodes, incomingBytes);
        top("Outgoing", outgoingOpcodes, outgoingBytes);
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
