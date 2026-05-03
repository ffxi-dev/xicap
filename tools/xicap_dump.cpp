#include <xicap/xicap.h>

#include <ffxi/entity.h>
#include <ffxi/inventory.h>
#include <ffxi/player.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>

const char* JobNames[] = {
    "NON", "WAR", "MNK", "WHM", "BLM", "RDM", "THF", "PLD", "DRK", "BST", "BRD", "RNG", "SAM", "NIN", "DRG", "SMN", "BLU", "COR", "PUP", "DNC", "SCH", "GEO", "RUN"
};

auto formatTimestamp(uint64_t ms) -> std::string
{
    std::time_t seconds = static_cast<std::time_t>(ms / 1000);
    std::tm     tm{};
    localtime_s(&tm, &seconds);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setfill('0') << std::setw(3) << (ms % 1000);
    return oss.str();
}

auto formatDuration(const uint64_t ms) -> std::string
{
    uint64_t seconds = ms / 1000;
    uint64_t minutes = seconds / 60;
    uint64_t hours   = minutes / 60;

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

auto hexDump(std::span<const std::byte> data, size_t maxBytes = 64) -> void
{
    size_t len = std::min(data.size(), maxBytes);
    for (size_t i = 0; i < len; ++i)
    {
        if (i > 0 && i % 16 == 0)
            std::cout << "\n         ";
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]) << " ";
    }
    if (data.size() > maxBytes)
    {
        std::cout << "... (" << std::dec << (data.size() - maxBytes) << " more bytes)";
    }
    std::cout << std::dec << "\n";
}

int main(int argc, char* argv[])
{
    bool        dumpPackets = false;
    uint64_t    limit       = 0;
    std::string filename;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--dump")
        {
            dumpPackets = true;
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
        std::cerr << "Usage: " << argv[0] << " [--dump] [--limit N] <file.xicap>\n";
        std::cerr << "  --dump    Show packet hex dumps\n";
        std::cerr << "  --limit N Only show first N packets\n";
        return 1;
    }

    try
    {
        const auto    fileSize = std::filesystem::file_size(filename);
        xicap::Reader reader(filename);

        std::cout << "=== XICAP File Info ===\n";
        std::cout << "Version:        " << static_cast<int>(reader.versionMajor()) << "."
                  << static_cast<int>(reader.versionMinor()) << "\n";
        std::cout << "Client:         " << reader.clientVersion() << "\n";
        const auto agent = reader.captureAgent();
        if (!agent.empty())
        {
            std::cout << "Capture Agent:  " << agent << "\n";
        }
        if (reader.startZoneId() != 0)
        {
            std::cout << "Start Zone:     " << reader.startZoneId() << "\n";
        }
        std::cout << "Start Time:     " << formatTimestamp(reader.startTimestamp()) << "\n";

        const auto& lobby = reader.lobby();
        if (lobby.contentId != 0)
        {
            std::cout << "\n=== Character Info (Lobby) ===\n";
            std::string charName(lobby.characterName.data(), strnlen(lobby.characterName.data(), 16));
            std::string worldName(lobby.worldName.data(), strnlen(lobby.worldName.data(), 16));
            std::cout << "Character:      " << charName << " @ " << worldName << "\n";
            std::cout << "Content ID:     " << lobby.contentId << "\n";
            std::cout << "World ID:       " << lobby.worldId << "\n";
        }

        if (const auto* snap = reader.getExtension(xicap::EXT_LOBBY_SNAPSHOT))
        {
            std::cout << "Lobby snapshot: " << snap->data.size() << " bytes\n";
        }
        std::cout << "Duration:       " << formatDuration(reader.durationMs()) << "\n";
        std::cout << "File Size:      " << formatBytes(fileSize) << "\n";
        std::cout << "Total Frames:   " << reader.totalFrames() << (reader.hasFooter() ? "" : " (truncated — no footer)") << "\n";

        // Extensions
        const auto& exts = reader.extensions();
        if (!exts.empty())
        {
            std::cout << "\n=== Extensions ===\n";

            uint32_t playerCount = 0, inventoryCount = 0, entityCount = 0, otherCount = 0;
            for (const auto& ext : exts)
            {
                switch (ext.type)
                {
                    case xicap::EXT_PLAYER:
                        ++playerCount;
                        break;
                    case xicap::EXT_INVENTORY:
                        ++inventoryCount;
                        break;
                    case xicap::EXT_ENTITY:
                        ++entityCount;
                        break;
                    default:
                        ++otherCount;
                        break;
                }
            }

            if (playerCount > 0)
                std::cout << "  Player snapshots:    " << playerCount << "\n";
            if (inventoryCount > 0)
                std::cout << "  Inventory snapshots: " << inventoryCount << "\n";
            if (entityCount > 0)
                std::cout << "  Entity snapshots:    " << entityCount << "\n";
            if (otherCount > 0)
                std::cout << "  Other extensions:    " << otherCount << "\n";

            for (const auto& ext : exts)
            {
                if (ext.type == xicap::EXT_PLAYER && ext.data.size() >= sizeof(Ashita::FFXI::player_t))
                {
                    const auto* p       = reinterpret_cast<const Ashita::FFXI::player_t*>(ext.data.data());
                    const char* mainJob = (p->MainJob < 23) ? JobNames[p->MainJob] : "???";
                    const char* subJob  = (p->SubJob < 23) ? JobNames[p->SubJob] : "???";
                    std::cout << "\n  [Player] " << mainJob << static_cast<int>(p->MainJobLevel)
                              << "/" << subJob << static_cast<int>(p->SubJobLevel)
                              << " | HP: " << p->HPMax << " MP: " << p->MPMax
                              << " | ATK: " << p->Attack << " DEF: " << p->Defense
                              << "\n           STR:" << p->Stats.Strength << " DEX:" << p->Stats.Dexterity
                              << " VIT:" << p->Stats.Vitality << " AGI:" << p->Stats.Agility
                              << " INT:" << p->Stats.Intelligence << " MND:" << p->Stats.Mind
                              << " CHR:" << p->Stats.Charisma << "\n";
                }
                else if (ext.type == xicap::EXT_INVENTORY && ext.data.size() >= sizeof(Ashita::FFXI::inventory_t))
                {
                    const auto* inv = reinterpret_cast<const Ashita::FFXI::inventory_t*>(ext.data.data());

                    const char* slotNames[] = {
                        "Main", "Sub", "Range", "Ammo", "Head", "Body", "Hands", "Legs", "Feet", "Neck", "Waist", "Ear1", "Ear2", "Ring1", "Ring2", "Back"
                    };

                    std::cout << "\n  [Equipment]\n";
                    for (size_t s = 0; s < 16; ++s)
                    {
                        const auto& eq        = inv->Equipment[s];
                        uint8_t     container = (eq.Index >> 8) & 0xFF;
                        uint8_t     index     = eq.Index & 0xFF;

                        if (container < 18 && index < 81)
                        {
                            const auto& item = inv->Containers[container].Items[index];
                            if (item.Id != 0)
                            {
                                std::cout << "    " << std::setw(6) << std::left << slotNames[s]
                                          << ": ID " << item.Id << "\n";
                            }
                        }
                    }

                    const char* containerNames[] = {
                        "Inventory", "Safe", "Storage", "Temporary", "Locker", "Satchel", "Sack", "Case", "Wardrobe", "Safe2", "Wardrobe2", "Wardrobe3", "Wardrobe4", "Wardrobe5", "Wardrobe6", "Wardrobe7", "Wardrobe8", "Recycle"
                    };

                    std::cout << "\n  [Inventory]\n";
                    for (size_t c = 0; c < 18; ++c)
                    {
                        std::vector<std::pair<uint16_t, uint32_t>> items;
                        for (size_t i = 0; i < 81; ++i)
                        {
                            const auto& item = inv->Containers[c].Items[i];
                            if (item.Id != 0)
                                items.emplace_back(item.Id, item.Count);
                        }
                        if (!items.empty())
                        {
                            std::cout << "    " << containerNames[c] << " (" << items.size() << " items):\n";
                            for (const auto& [id, count] : items)
                            {
                                std::cout << "      ID: " << std::setw(5) << id << " x" << count << "\n";
                            }
                        }
                    }
                }
                else if (ext.type == xicap::EXT_ENTITY && ext.data.size() >= sizeof(Ashita::FFXI::entity_t))
                {
                    const auto* e = reinterpret_cast<const Ashita::FFXI::entity_t*>(ext.data.data());
                    std::string name(reinterpret_cast<const char*>(e->Name), strnlen(reinterpret_cast<const char*>(e->Name), 28));

                    if (!name.empty() && e->SpawnFlags != 0)
                    {
                        std::cout << "  [Entity] " << std::setw(20) << std::left << name
                                  << " | ID: " << std::setw(5) << e->ServerId
                                  << " | Idx: " << std::setw(4) << e->TargetIndex
                                  << " | HP: " << std::setw(3) << static_cast<int>(e->HPPercent) << "%"
                                  << " | Type: " << static_cast<int>(e->Type)
                                  << " | Pos: (" << std::fixed << std::setprecision(1)
                                  << e->Movement.LocalPosition.X << ", " << e->Movement.LocalPosition.Y << ")\n";
                    }
                }
            }
        }

        auto zones = reader.listZones();
        if (!zones.empty())
        {
            std::cout << "\n=== Zones Visited ===\n";
            for (const auto& zone : zones)
            {
                std::cout << "  Zone " << zone.zoneId << " at " << formatTimestamp(zone.timestamp) << "\n";
            }
        }

        std::cout << "\n=== Scanning Packets ===\n";

        std::map<uint16_t, uint64_t> incomingOpcodes;
        std::map<uint16_t, uint64_t> outgoingOpcodes;
        std::map<uint16_t, uint64_t> incomingBytes;
        std::map<uint16_t, uint64_t> outgoingBytes;
        uint64_t                     totalIncoming      = 0;
        uint64_t                     totalOutgoing      = 0;
        uint64_t                     totalIncomingBytes = 0;
        uint64_t                     totalOutgoingBytes = 0;
        uint64_t                     packetCount        = 0;
        uint64_t                     minPacketSize      = UINT64_MAX;
        uint64_t                     maxPacketSize      = 0;

        for (const auto& packet : reader)
        {
            const auto pktSize = packet.data.size();

            if (packet.direction == xicap::PacketDirection::ServerToClient)
            {
                incomingOpcodes[packet.opcode]++;
                incomingBytes[packet.opcode] += pktSize;
                totalIncoming++;
                totalIncomingBytes += pktSize;
            }
            else
            {
                outgoingOpcodes[packet.opcode]++;
                outgoingBytes[packet.opcode] += pktSize;
                totalOutgoing++;
                totalOutgoingBytes += pktSize;
            }

            if (pktSize < minPacketSize)
                minPacketSize = pktSize;
            if (pktSize > maxPacketSize)
                maxPacketSize = pktSize;

            if (dumpPackets && (limit == 0 || packetCount < limit))
            {
                std::cout << "[" << formatTimestamp(packet.timestamp) << "] "
                          << (packet.direction == xicap::PacketDirection::ServerToClient ? "S2C" : "C2S")
                          << " 0x" << std::hex << std::setfill('0') << std::setw(3) << packet.opcode << std::dec
                          << " (" << packet.data.size() << " bytes)\n";
                std::cout << "         ";
                hexDump(packet.data);
            }

            packetCount++;
        }

        const uint64_t totalRawBytes    = totalIncomingBytes + totalOutgoingBytes;
        const double   compressionRatio = totalRawBytes > 0 ? static_cast<double>(totalRawBytes) / fileSize : 0;
        const uint64_t durationMs       = reader.durationMs();
        const double   packetsPerSec    = durationMs > 0 ? (packetCount * 1000.0) / durationMs : 0;
        const double   bytesPerSec      = durationMs > 0 ? (totalRawBytes * 1000.0) / durationMs : 0;

        std::cout << "\n=== Packet Summary ===\n";
        std::cout << "Total Packets:  " << packetCount << "\n";
        std::cout << "Server->Client: " << totalIncoming << " packets, " << formatBytes(totalIncomingBytes) << "\n";
        std::cout << "Client->Server: " << totalOutgoing << " packets, " << formatBytes(totalOutgoingBytes) << "\n";

        std::cout << "\n=== Size Stats ===\n";
        std::cout << "Raw Data:       " << formatBytes(totalRawBytes) << "\n";
        std::cout << "Compressed:     " << formatBytes(fileSize) << "\n";
        std::cout << "Ratio:          " << std::fixed << std::setprecision(2) << compressionRatio << "x\n";
        if (packetCount > 0)
        {
            std::cout << "Avg Pkt Size:   " << (totalRawBytes / packetCount) << " bytes\n";
            std::cout << "Min Pkt Size:   " << minPacketSize << " bytes\n";
            std::cout << "Max Pkt Size:   " << maxPacketSize << " bytes\n";
        }

        std::cout << "\n=== Throughput ===\n";
        std::cout << "Packets/sec:    " << std::fixed << std::setprecision(1) << packetsPerSec << "\n";
        std::cout << "Data Rate:      " << formatBytes(static_cast<uint64_t>(bytesPerSec)) << "/s\n";
        if (reader.totalFrames() > 0)
        {
            std::cout << "Pkts/Frame:     " << std::fixed << std::setprecision(1)
                      << (static_cast<double>(packetCount) / reader.totalFrames()) << "\n";
        }

        std::cout << "\n=== Top Incoming Opcodes (by count) ===\n";
        std::vector<std::pair<uint16_t, uint64_t>> sortedIn(incomingOpcodes.begin(), incomingOpcodes.end());
        std::ranges::sort(sortedIn, [](const auto& a, const auto& b)
                          {
                              return a.second > b.second;
                          });
        for (size_t i = 0; i < std::min<size_t>(10, sortedIn.size()); ++i)
        {
            const auto opcode = sortedIn[i].first;
            std::cout << "  0x" << std::hex << std::setfill('0') << std::setw(3) << opcode << std::dec
                      << ": " << sortedIn[i].second << " pkts, " << formatBytes(incomingBytes[opcode]) << "\n";
        }

        std::cout << "\n=== Top Outgoing Opcodes (by count) ===\n";
        std::vector<std::pair<uint16_t, uint64_t>> sortedOut(outgoingOpcodes.begin(), outgoingOpcodes.end());
        std::ranges::sort(sortedOut, [](const auto& a, const auto& b)
                          {
                              return a.second > b.second;
                          });
        for (size_t i = 0; i < std::min<size_t>(10, sortedOut.size()); ++i)
        {
            const auto opcode = sortedOut[i].first;
            std::cout << "  0x" << std::hex << std::setfill('0') << std::setw(3) << opcode << std::dec
                      << ": " << sortedOut[i].second << " pkts, " << formatBytes(outgoingBytes[opcode]) << "\n";
        }

        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
