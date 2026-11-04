#pragma once

#include <xicap/xicap.h>

#include "craft.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <random>
#include <string>
#include <vector>

namespace test
{

namespace fs = std::filesystem;
using namespace xicap;

inline std::atomic<uint64_t> g_tempCounter{ 0 };
// ctest runs each test case in its own process, perhaps at once.
inline const auto g_process = std::to_string(std::random_device{}());

struct TempCapture
{
    fs::path path = fs::temp_directory_path() / fs::path{ "xicap-test-" + g_process + "-" + std::to_string(g_tempCounter.fetch_add(1)) + ".xicap" };
    ~TempCapture()
    {
        std::error_code ec;
        fs::remove(path, ec);
        fs::remove(fs::path(path).concat(".tmp"), ec);
    }
};

inline constexpr uint64_t T0 = 1'790'000'000'000ULL;

inline auto seed(uint8_t fill = 7) -> SecretSeed
{
    SecretSeed s{};
    s.fill(fill);
    return s;
}

inline auto config() -> WriterConfig
{
    WriterConfig cfg{};
    cfg.clientVersion         = "test-client";
    cfg.captureAgent          = "xicap tests";
    cfg.character.contentId   = 0x01020304;
    cfg.character.worldId     = 42;
    cfg.character.characterId = 0x0A0B0C0D;
    std::memcpy(cfg.character.characterName.data(), "Nouurs", 6);
    std::memcpy(cfg.character.worldName.data(), "Asura", 5);
    cfg.network     = Network::Retail;
    cfg.signingSeed = seed();
    return cfg;
}

// Each frame its own whole stream, so tests can decode and re-encode one frame alone.
inline auto alone() -> FramePolicy
{
    FramePolicy p{};
    p.restartBytes = 0;
    return p;
}

using craft::gamePacket;

inline auto zoneIn(uint16_t zone, const char* name = "Nouurs", uint32_t id = 0x0A0B0C0D) -> std::vector<std::byte>
{
    auto p = gamePacket(FFXIPacket::LOGIN_ZONE, 160, 0);
    std::memcpy(p.data() + FFXIPacket::LOGIN_ZONE_NO_OFFSET, &zone, sizeof(zone));
    std::memcpy(p.data() + FFXIPacket::LOGIN_UNIQUE_NO_OFFSET, &id, sizeof(id));
    std::memcpy(p.data() + FFXIPacket::LOGIN_NAME_OFFSET, name, std::strlen(name));
    return p;
}

struct Owned
{
    uint64_t                timestamp;
    uint8_t                 channel;
    uint16_t                opcode;
    uint16_t                flags;
    PacketDirection         direction;
    std::vector<uint8_t>    data;
    std::vector<ReadMarker> markers;

    auto operator==(const Owned& o) const -> bool
    {
        return timestamp == o.timestamp && channel == o.channel && opcode == o.opcode && flags == o.flags && data == o.data &&
               std::ranges::equal(markers, o.markers, [](const ReadMarker& a, const ReadMarker& b)
                                  {
                                      return a.kind == b.kind && a.text == b.text;
                                  });
    }
};

inline auto own(const ReadPacket& p) -> Owned
{
    const auto* d = reinterpret_cast<const uint8_t*>(p.data.data());
    return { p.timestamp, p.channel, p.opcode, p.flags, p.direction, { d, d + p.data.size() }, { p.markers.begin(), p.markers.end() } };
}

template <typename R>
    requires requires(R& r, ReadPacket& p) { r.next(p); }
auto readAll(R& reader) -> std::vector<Owned>
{
    std::vector<Owned> out;
    ReadPacket         p{};
    while (reader.next(p))
    {
        out.push_back(own(p));
    }
    return out;
}

inline auto readAll(const fs::path& path, ReaderOptions options = {}) -> std::vector<Owned>
{
    Reader reader(path, options);
    return readAll(reader);
}

inline auto truncateAt(const fs::path& path, size_t size) -> void
{
    auto bytes = craft::bytesOf(path);
    bytes.resize(size);
    craft::save(path, bytes);
}

// Writes `frames` packet frames of `perFrame` packets each, one second apart.
inline auto writeFrames(const fs::path& path, int frames, int perFrame = 3, FramePolicy policy = {}) -> void
{
    Writer w(path, config(), policy);
    for (int f = 0; f < frames; ++f)
    {
        for (int i = 0; i < perFrame; ++i)
        {
            w.write(T0 + static_cast<uint64_t>(f) * 1000 + static_cast<uint64_t>(i), PacketDirection::ServerToClient, gamePacket(static_cast<uint16_t>(0x100 + f), 16, static_cast<uint8_t>(f), static_cast<uint16_t>(f * perFrame + i)));
        }
        w.flush();
    }
    w.close();
}

} // namespace test
