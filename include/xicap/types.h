#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace xicap
{

inline constexpr size_t CLIENT_VERSION_MAX_LEN = 32;
inline constexpr size_t CAPTURE_AGENT_MAX_LEN  = 32;
inline constexpr size_t CHARACTER_NAME_MAX_LEN = 16;
inline constexpr size_t WORLD_NAME_MAX_LEN     = 16;

#pragma pack(push, 1)

// Stable POL lobby identifiers carried in the Header. The runtime
// TC_OPERATION_MAKE blob lives in EXT_LOBBY_SNAPSHOT, not here.
struct LobbyIdentity
{
    uint32_t                                 contentId;      // POL ffxi_id
    uint16_t                                 worldContentId; // ffxi_id_world
    uint16_t                                 worldId;
    uint16_t                                 status;
    uint8_t                                  pendingRename : 1;
    uint8_t                                  pendingRaceChange : 1;
    uint8_t                                  reservedFlags : 6;
    uint8_t                                  worldTableIndex; // ffxi_id_world_tbl
    std::array<char, CHARACTER_NAME_MAX_LEN> characterName;
    std::array<char, WORLD_NAME_MAX_LEN>     worldName;
};
static_assert(sizeof(LobbyIdentity) == 44);

// On-disk file header. End-of-capture fields are back-patched on clean close
// and remain zero on truncated captures.
struct Header
{
    uint32_t                                 magic;
    uint8_t                                  versionMajor;
    uint8_t                                  versionMinor;
    std::array<char, CAPTURE_AGENT_MAX_LEN>  captureAgent;
    uint16_t                                 extensionCount;
    std::array<char, CLIENT_VERSION_MAX_LEN> clientVersion;
    uint16_t                                 startZoneId;
    uint64_t                                 startTimestamp;
    LobbyIdentity                            lobby;
    uint8_t                                  startWeather;
    uint8_t                                  padding0;
    uint32_t                                 dictionaryId;
    uint64_t                                 endTimestamp;     // 0 on truncated captures
    uint64_t                                 totalPacketCount; // 0 on truncated captures
    uint16_t                                 endZoneId;        // 0 on truncated captures
    std::array<uint8_t, 106>                 reserved;
};
static_assert(sizeof(Header) == 256);

struct ExtensionBlockHeader
{
    uint32_t type;
    uint32_t length;
};
static_assert(sizeof(ExtensionBlockHeader) == 8);

// Frame layout on disk:
//   FrameHeader (20 B)
//   compressed payload (compressedSize bytes)
//   uint32_t crc32          // CRC-32/IEEE over (FrameHeader bytes + compressed payload)
struct FrameHeader
{
    uint32_t compressedSize;
    uint32_t packetCount;
    uint64_t baseTimestamp;
    uint16_t zoneId;
    uint16_t markerCount;
};
static_assert(sizeof(FrameHeader) == 20);

// Followed by char text[textLength] when textLength > 0.
struct FrameMarker
{
    uint16_t packetIndex;
    uint16_t textLength;
};
static_assert(sizeof(FrameMarker) == 4);

// deltaMs is from previous packet, clipped to UINT16_MAX (writers force a frame
// flush before that ever happens, so the clip is unreachable in practice).
// flags bit 0 = direction (0 = server→client, 1 = client→server). Other bits
// are reserved and must be zero.
// Followed by uint8_t data[length] (full FFXI packet, including its 4-byte
// header).
struct PacketEntry
{
    uint16_t deltaMs;
    uint16_t length;
    uint16_t opcode;
    uint16_t flags;
};
static_assert(sizeof(PacketEntry) == 8);

inline constexpr uint16_t PACKET_FLAG_DIRECTION_BIT = 0x0001;

// One per frame, present only on clean close.
struct FooterIndexEntry
{
    uint64_t timestamp;
    uint64_t fileOffset;
    uint16_t zoneId;
    uint8_t  reserved[6];
};
static_assert(sizeof(FooterIndexEntry) == 24);

// Last 24 bytes of the file. Absent => truncated capture; reader falls back
// to scanning frames.
struct FooterTrailer
{
    uint32_t magic;
    uint32_t entryCount;
    uint64_t indexOffset;
    uint8_t  reserved[8];
};
static_assert(sizeof(FooterTrailer) == 24);

#pragma pack(pop)

enum class PacketDirection : uint8_t
{
    ServerToClient = 0,
    ClientToServer = 1
};

struct ReadMarker
{
    std::string text;
};

// Yielded by Reader::next. ``data`` and ``markers`` reference internal Reader
// buffers and are invalidated by the next call to ``next``, ``seekTo*``,
// ``reset``, or destruction. Callers that need ownership should copy.
struct ReadPacket
{
    uint64_t                    timestamp;
    uint16_t                    opcode;
    PacketDirection             direction;
    std::span<const std::byte>  data;
    std::span<const ReadMarker> markers;
};

struct ExtensionBlock
{
    uint32_t             type;
    std::vector<uint8_t> data;
};

// Well-known extension block type ids. See FORMAT.md.
enum ExtensionType : uint32_t
{
    EXT_PLAYER         = 0x0001,
    EXT_INVENTORY      = 0x0002,
    EXT_ENTITY         = 0x0003,
    EXT_MISSIONS       = 0x0004,
    EXT_SPELLS         = 0x0005,
    EXT_ABILITIES      = 0x0006,
    EXT_LOBBY_SNAPSHOT = 0x0007,
    // Format-level, not agent data: the zstd dictionary the capture was written
    // with. The Reader consumes it and does not surface it in extensions().
    EXT_ZSTD_DICT = 0x0008,
};

enum class ErrorCode
{
    OpenFailed,
    BadMagic,
    UnsupportedVersion,
    DictionaryMismatch,
    ShortHeader,
    ShortExtension,
    ExtensionTooLarge,
    CorruptFrame,
    FrameChecksumMismatch,
    DecompressFailed,
    ZstdContextFailed,
    WriterClosed,
    AddExtensionAfterPackets,
    AddMarkerWithoutPacket,
    // Appended only — the bindings mirror this enum by ordinal.
    PacketTooLarge,
    CompressFailed,
};

class Error : public std::runtime_error
{
public:
    Error(ErrorCode code, std::string message)
    : std::runtime_error(std::move(message))
    , code_(code)
    {
    }

    [[nodiscard]] auto code() const noexcept -> ErrorCode
    {
        return code_;
    }

private:
    ErrorCode code_;
};

enum class SeekResult
{
    Ok,
    EmptyIndex,
    OutOfRange,
    NotFound,
};

} // namespace xicap
