#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace xicap
{

using CaptureId = std::array<uint8_t, 16>;

enum class Origin : uint8_t
{
    Unknown   = 0,
    Live      = 1,
    Converted = 2,
};

enum class Network : uint8_t
{
    Unknown = 0,
    Retail  = 1,
    Private = 2,
};

// Readers pass on packets of channels this enum does not name.
enum class Channel : uint8_t
{
    Game   = 0,
    Search = 1,
};

// Readers treat kinds this enum does not name as notes.
enum class MarkerKind : uint8_t
{
    Note   = 0,
    Login  = 1,
    Logout = 2,
};

enum class PacketDirection : uint8_t
{
    ServerToClient = 0,
    ClientToServer = 1,
};

namespace PacketFlag
{
inline constexpr uint16_t ClientToServer = 0x0001;
inline constexpr uint16_t Injected       = 0x0002;
inline constexpr uint16_t Blocked        = 0x0004;
inline constexpr uint16_t Modified       = 0x0008;
inline constexpr uint16_t FirstInChunk   = 0x0010;
inline constexpr uint16_t Provenance     = Injected | Blocked | Modified | FirstInChunk;
inline constexpr uint16_t Excluded       = 0x0100;
inline constexpr uint16_t Redacted       = 0x0200;
} // namespace PacketFlag

struct Character
{
    uint32_t    contentId{};
    uint32_t    characterId{};
    std::string name;
    std::string world;

    auto operator==(const Character&) const -> bool = default;
};

// What a converted capture records about its source.
struct Source
{
    std::string          format;
    std::string          formatVersion;
    uint32_t             skippedRecords{};
    std::vector<uint8_t> metadata;

    auto operator==(const Source&) const -> bool = default;
};

struct Marker
{
    MarkerKind  kind{};
    std::string text;

    auto operator==(const Marker&) const -> bool = default;
};

// A packet as a reader yields it. data and markers point into the reader and last until its next call.
struct Packet
{
    uint64_t                   timestamp{};
    uint16_t                   flags{};
    uint8_t                    channel{};
    uint16_t                   opcode{};
    std::span<const std::byte> data;
    std::span<const Marker>    markers; // the markers just before this packet

    [[nodiscard]] auto direction() const noexcept -> PacketDirection
    {
        return static_cast<PacketDirection>(flags & PacketFlag::ClientToServer);
    }
};

// A packet as a writer is given it.
struct OutPacket
{
    uint64_t                   timestamp{};
    PacketDirection            direction{};
    std::span<const std::byte> data;
    uint8_t                    channel = static_cast<uint8_t>(Channel::Game);
    uint16_t                   opcode{};     // ignored on the game channel, where the packet's header holds it
    uint16_t                   provenance{}; // PacketFlag::Provenance bits
};

// A packet as a writer stores it, after its exclusion policy.
struct StoredPacket
{
    uint16_t               opcode{};
    uint16_t               flags{};
    std::vector<std::byte> data;
};

class Error : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

} // namespace xicap
