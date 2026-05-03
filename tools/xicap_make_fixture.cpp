// Generates a deterministic .xicap file used by the JS test suite. The exact
// contents are described inline below so the JS test can assert against them.

#include <xicap/xicap.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <vector>

namespace
{
auto makePacket(uint16_t opcode, uint16_t size, uint8_t fill) -> std::vector<std::byte>
{
    std::vector<std::byte> p(size);
    const uint16_t         hdr = static_cast<uint16_t>(((size & 0x7F) << 9) | (opcode & 0x1FF));
    p[0]                       = std::byte(hdr & 0xFF);
    p[1]                       = std::byte(hdr >> 8);
    for (size_t i = 4; i < size; ++i)
    {
        p[i] = std::byte(fill);
    }
    return p;
}
} // namespace

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cerr << "usage: " << argv[0] << " <output.xicap>\n";
        return 1;
    }

    xicap::WriterConfig cfg{};
    cfg.clientVersion          = "fixture-1.0";
    cfg.captureAgent           = "xicap_make_fixture";
    cfg.startZoneId            = 100;
    cfg.lobby.contentId        = 0xDEADBEEFu;
    cfg.lobby.worldId          = 42;
    cfg.lobby.pendingRename    = 1;
    std::memcpy(cfg.lobby.characterName.data(), "Mehdi", 5);
    std::memcpy(cfg.lobby.worldName.data(), "Asura", 5);

    xicap::Writer w(argv[1], cfg);

    const std::array<uint8_t, 5> ext = { 1, 2, 3, 4, 5 };
    w.addExtension(xicap::EXT_PLAYER, std::as_bytes(std::span{ ext }));

    constexpr uint64_t startTs = 1'700'000'000'000ULL;
    for (int i = 0; i < 50; ++i)
    {
        const auto pkt = makePacket(static_cast<uint16_t>(0x100 + (i % 4)), 32, static_cast<uint8_t>(i));
        w.write(startTs + i * 50,
                (i % 2) ? xicap::PacketDirection::ClientToServer : xicap::PacketDirection::ServerToClient,
                pkt);
        if (i == 9)
        {
            w.addMarker("after-tenth");
        }
    }

    w.close();
    return 0;
}
