#pragma once

#include <xicap/xicap.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <vector>

namespace test
{

// A game packet: id, size in words from its length, sync, then bytes of fill.
inline auto gamePacket(uint16_t id, size_t length, uint16_t sync, uint8_t fill = 0) -> std::vector<std::byte>
{
    std::vector<std::byte> p(length, std::byte{ fill });
    const auto             word = static_cast<uint16_t>((id & 0x1FF) | ((length / 4) << 9));
    p[0]                        = static_cast<std::byte>(word);
    p[1]                        = static_cast<std::byte>(word >> 8);
    p[2]                        = static_cast<std::byte>(sync);
    p[3]                        = static_cast<std::byte>(sync >> 8);
    return p;
}

inline auto out(uint64_t timestamp, const std::vector<std::byte>& data, xicap::PacketDirection direction = xicap::PacketDirection::ServerToClient) -> xicap::OutPacket
{
    return { .timestamp = timestamp, .direction = direction, .data = data };
}

inline auto metadata() -> xicap::Metadata
{
    return {
        .captureId     = { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 },
        .serverKind    = xicap::ServerKind::Retail,
        .captureAgent  = "xicap tests",
        .clientVersion = "30251101_2",
        .character     = { .contentId = 0x01020304, .characterId = 0x0A0B0C0D, .name = "Rhavyn", .world = "Asura" },
    };
}

// A packet that owns its bytes and markers.
struct Owned
{
    uint64_t                   timestamp{};
    uint16_t                   flags{};
    uint8_t                    channel{};
    uint16_t                   opcode{};
    std::vector<std::byte>     data;
    std::vector<xicap::Marker> markers;

    explicit Owned(const xicap::Packet& p)
    : timestamp(p.timestamp)
    , flags(p.flags)
    , channel(p.channel)
    , opcode(p.opcode)
    , data(p.data.begin(), p.data.end())
    , markers(p.markers.begin(), p.markers.end())
    {
    }

    auto operator==(const Owned&) const -> bool = default;
};

inline auto readAll(const std::filesystem::path& path) -> std::vector<Owned>
{
    xicap::Reader      r(path);
    std::vector<Owned> packets;
    for (const auto& p : r)
    {
        packets.emplace_back(p);
    }

    return packets;
}

inline auto bytesOf(const std::filesystem::path& path) -> std::vector<uint8_t>
{
    std::ifstream in(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(in), {} };
}

inline auto save(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) -> void
{
    std::ofstream(path, std::ios::binary).write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

// A file in the temporary directory, removed with the object.
class TempFile
{
public:
    TempFile()
    {
        std::random_device rd;
        path_ = std::filesystem::temp_directory_path() / ("xicap-test-" + std::to_string(rd()) + std::to_string(rd()) + ".xicap");
    }

    ~TempFile()
    {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    TempFile(const TempFile&)                    = delete;
    TempFile(TempFile&&)                         = delete;
    auto operator=(const TempFile&) -> TempFile& = delete;
    auto operator=(TempFile&&) -> TempFile&      = delete;

    [[nodiscard]] auto path() const noexcept -> const std::filesystem::path&
    {
        return path_;
    }

    operator const std::filesystem::path&() const noexcept
    {
        return path_;
    }

private:
    std::filesystem::path path_;
};

} // namespace test
