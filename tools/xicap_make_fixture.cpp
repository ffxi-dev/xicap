// Generates a deterministic format 3 .xicap file for the Python and JS test
// suites. Its contents are described inline so those tests can assert on them.

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
    std::vector<std::byte> p(size, std::byte(fill));
    const auto             hdr = static_cast<uint16_t>((((size / 4) & 0x7F) << 9) | (opcode & 0x1FF));
    p[0]                       = std::byte(hdr & 0xFF);
    p[1]                       = std::byte(hdr >> 8);
    p[2]                       = std::byte{ 0 };
    p[3]                       = std::byte{ 0 };
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
    cfg.clientVersion       = "fixture-1.0";
    cfg.captureAgent        = "xicap_make_fixture";
    cfg.character.contentId = 0xDEADBEEFu;
    cfg.character.worldId   = 42;
    std::memcpy(cfg.character.characterName.data(), "Mehdi", 5);
    std::memcpy(cfg.character.worldName.data(), "Asura", 5);
    cfg.network = xicap::Network::Retail;
    cfg.captureId.fill(0x11);
    cfg.signingSeed.fill(0x22);

    xicap::Writer w(argv[1], cfg);

    const std::array<uint8_t, 5> ext = { 1, 2, 3, 4, 5 };
    w.addExtension(0x8000, std::as_bytes(std::span{ ext }));

    // 50 game packets, 50 ms apart: opcode 0x100 + i % 4, 32 bytes filled with
    // i, odd ones client to server. A note marker sits before packet 10.
    constexpr uint64_t startTs = 1'700'000'000'000ULL;
    for (int i = 0; i < 50; ++i)
    {
        if (i == 10)
        {
            w.mark(xicap::MarkerKind::Note, "tenth");
        }
        const auto pkt = makePacket(static_cast<uint16_t>(0x100 + (i % 4)), 32, static_cast<uint8_t>(i));
        w.write(startTs + i * 50,
                (i % 2) ? xicap::PacketDirection::ClientToServer : xicap::PacketDirection::ServerToClient,
                pkt);
    }
    // Then one 40-byte search reply, opcode 5.
    const std::vector<std::byte> search(40, std::byte{ 0x5A });
    w.write({ .timestamp = startTs + 2500, .direction = xicap::PacketDirection::ServerToClient, .data = search, .channel = 1, .opcode = 5 });

    w.close();
    return 0;
}
