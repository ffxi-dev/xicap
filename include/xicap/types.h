#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
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

using CaptureId  = std::array<uint8_t, 16>;
using PublicKey  = std::array<uint8_t, 32>;
using SecretSeed = std::array<uint8_t, 32>;
using Signature  = std::array<uint8_t, 64>;
using Digest     = std::array<uint8_t, 64>; // D(k), a SHA-512

enum class ClockSource : uint8_t
{
    Unknown   = 0,
    Live      = 1,
    Converted = 2,
};

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

enum class StartContext : uint8_t
{
    Unknown    = 0,
    Login      = 1,
    MidSession = 2,
};

// What the recorder kept of what players write. Readers refuse a mode they do not know. See FORMAT.md, Header.
enum class RecordingMode : uint8_t
{
    Default    = 0, // the exclusion policy stubs chat
    Everything = 1, // the exclusion policy has no rules: chat is kept
    Anonymous  = 2, // as Default, and names and player ids are pseudonyms
};

// Channel numbers come from the registry in FORMAT.md. Readers pass on
// packets of channels this enum does not name.
enum class Channel : uint8_t
{
    Game   = 0,
    Search = 1,
};

enum class FrameKind : uint8_t
{
    Checkpoint = 0x01,
    Packets    = 0x80,
};

enum class MarkerKind : uint8_t
{
    Note   = 0,
    Login  = 1,
    Logout = 2,
};

enum class PacketDirection : uint8_t
{
    ServerToClient = 0,
    ClientToServer = 1
};

namespace PacketFlag
{
inline constexpr uint16_t ClientToServer = 0x0001;
inline constexpr uint16_t Injected       = 0x0002;
inline constexpr uint16_t Blocked        = 0x0004;
inline constexpr uint16_t Modified       = 0x0008;
inline constexpr uint16_t FirstInChunk   = 0x0010;
inline constexpr uint16_t Provenance     = 0x00FE; // bits 1 to 7
inline constexpr uint16_t Excluded       = 0x0100;
inline constexpr uint16_t Redacted       = 0x0200;
inline constexpr uint16_t KnownRequired  = Excluded | Redacted;
inline constexpr uint16_t Required       = 0xFF00; // bits 8 to 15
} // namespace PacketFlag

#pragma pack(push, 1)

struct CharacterIdentity
{
    uint32_t                                 contentId;
    uint32_t                                 characterId;
    uint16_t                                 worldId;
    uint16_t                                 reserved;
    std::array<char, CHARACTER_NAME_MAX_LEN> characterName;
    std::array<char, WORLD_NAME_MAX_LEN>     worldName;
};
static_assert(sizeof(CharacterIdentity) == 44);

// Written once, with every field final. See FORMAT.md.
struct Header
{
    std::array<uint8_t, 8>                   magic;
    uint8_t                                  versionMajor;
    uint8_t                                  versionMinor;
    uint16_t                                 headerSize;
    uint32_t                                 extensionCount;
    uint64_t                                 reserved0;
    CaptureId                                captureId;
    CaptureId                                previousCaptureId;
    uint64_t                                 startTimestamp;
    std::array<uint8_t, 3>                   reserved1;
    ClockSource                              clockSource;
    Origin                                   origin;
    Network                                  network;
    StartContext                             startContext;
    RecordingMode                            recordingMode;
    uint32_t                                 dictionaryId;
    uint32_t                                 reserved3;
    PublicKey                                signingKey;
    std::array<char, CAPTURE_AGENT_MAX_LEN>  captureAgent;
    std::array<char, CLIENT_VERSION_MAX_LEN> clientVersion;
    CharacterIdentity                        character;
    std::array<uint8_t, 160>                 reserved4;
    uint32_t                                 headerCrc;
};
static_assert(sizeof(Header) == 384);
static_assert(offsetof(Header, startTimestamp) == 56);
static_assert(offsetof(Header, clockSource) == 67);
static_assert(offsetof(Header, startContext) == 70);
static_assert(offsetof(Header, recordingMode) == 71);
static_assert(offsetof(Header, dictionaryId) == 72);
static_assert(offsetof(Header, signingKey) == 80);
static_assert(offsetof(Header, captureAgent) == 112);
static_assert(offsetof(Header, clientVersion) == 144);
static_assert(offsetof(Header, character) == 176);
static_assert(offsetof(Header, headerCrc) == 380);

// Followed by the payload, then a u32 CRC of type, length, and payload.
struct ExtensionBlockHeader
{
    uint32_t type;
    uint32_t length;
};
static_assert(sizeof(ExtensionBlockHeader) == 8);

// Followed by payloadSize bytes, then a u32 CRC of everything from magic on.
struct FrameHeader
{
    uint32_t  magic;
    FrameKind kind;
    uint8_t   frameFlags;
    uint16_t  markerCount;
    uint32_t  payloadSize;
    uint32_t  packetCount;
    uint64_t  baseTimestamp;
    uint16_t  zoneId;
    uint16_t  reserved;
    uint32_t  plainSize;
};
static_assert(sizeof(FrameHeader) == 32);
static_assert(offsetof(FrameHeader, plainSize) == 28);

namespace FrameFlag
{
inline constexpr uint8_t Restart = 0x01; // this packet frame starts a zstd stream
} // namespace FrameFlag

struct CheckpointPayload
{
    uint64_t  packets;
    Digest    digest;
    Signature signature;
};
static_assert(sizeof(CheckpointPayload) == 136);

struct FooterIndexEntry
{
    uint64_t timestamp;
    uint64_t fileOffset;
    uint16_t zoneId;
    uint8_t  flags; // IndexFlag
    uint8_t  reserved[5];
};
static_assert(sizeof(FooterIndexEntry) == 24);

namespace IndexFlag
{
inline constexpr uint8_t Restart = 0x01;
} // namespace IndexFlag

// What another program that rewrote the file signed.
struct SealBlock
{
    uint32_t                magic;
    uint32_t                reserved0;
    uint64_t                sealedAt;
    PublicKey               key;
    std::array<char, 32>    agent;
    Signature               signature;
    std::array<uint8_t, 12> reserved1;
    uint32_t                crc;
};
static_assert(sizeof(SealBlock) == 160);
static_assert(offsetof(SealBlock, signature) == 80);
static_assert(offsetof(SealBlock, crc) == 156);

struct FooterTrailer
{
    uint64_t  endTimestamp;
    uint64_t  totalPacketCount;
    uint32_t  trailerFlags; // TrailerFlag
    uint32_t  entryCount;
    uint64_t  indexOffset;
    uint32_t  indexCrc;
    uint32_t  frameCount;
    Signature signature;
    uint32_t  trailerCrc;
    uint32_t  magic;
};
static_assert(sizeof(FooterTrailer) == 112);
static_assert(offsetof(FooterTrailer, signature) == 40);
static_assert(offsetof(FooterTrailer, trailerCrc) == 104);

namespace TrailerFlag
{
inline constexpr uint32_t Sealed      = 0x01; // a seal precedes the trailer
inline constexpr uint32_t EndUnsigned = 0x02; // the signer never signed the end; signature is zero
inline constexpr uint32_t Known       = Sealed | EndUnsigned;
} // namespace TrailerFlag

struct ExclusionPolicyHeader
{
    std::array<char, 32> name;
    uint32_t             version;
    uint16_t             ruleCount;
    uint16_t             reserved;
};
static_assert(sizeof(ExclusionPolicyHeader) == 40);

struct ExclusionRuleHeader
{
    uint8_t  channel;
    uint8_t  direction;
    uint8_t  action;
    uint8_t  reserved;
    uint16_t opcode;
    uint16_t rangeCount;
};
static_assert(sizeof(ExclusionRuleHeader) == 8);

struct SourceHeader
{
    std::array<char, 16>    format;
    std::array<char, 16>    formatVersion;
    uint32_t                skippedRecords;
    int32_t                 utcOffsetSeconds;
    std::array<uint8_t, 64> sourceHash;
    uint32_t                metadataLength;
};
static_assert(sizeof(SourceHeader) == 108);

// The SOURCE_SIGNER block's payload.
struct SourceSignerBlock
{
    PublicKey              signingKey;
    uint64_t               verifiedPackets;
    uint8_t                flags; // SourceSignerFlag
    std::array<uint8_t, 7> reserved;
};
static_assert(sizeof(SourceSignerBlock) == 48);

namespace SourceSignerFlag
{
inline constexpr uint8_t SignedToEnd = 0x01;
} // namespace SourceSignerFlag

#pragma pack(pop)

// Well-known extension block types. 0x0001 to 0x0008 held client memory copies
// and a zstd dictionary in earlier formats and are retired.
enum ExtensionType : uint32_t
{
    EXT_EXCLUSION_POLICY = 0x0009,
    EXT_SOURCE           = 0x000A,
    EXT_SOURCE_SIGNER    = 0x000B,
};

enum class ExclusionDirection : uint8_t
{
    ServerToClient = 0,
    ClientToServer = 1,
    Both           = 2,
};

enum class ExclusionAction : uint8_t
{
    Stub      = 1,
    ZeroRange = 2,
};

struct ByteRange
{
    uint32_t offset;
    uint32_t length; // 0xFFFFFFFF runs to the packet's end
};

struct ExclusionRule
{
    uint8_t                channel{};
    ExclusionDirection     direction{};
    ExclusionAction        action{};
    uint16_t               opcode{};
    std::vector<ByteRange> ranges;
};

struct ExclusionPolicy
{
    std::string                name;
    uint32_t                   version{};
    std::vector<ExclusionRule> rules;
};

// A source that was a signed capture: its signer, and what its signatures covered when its packets were taken.
struct SourceSigner
{
    PublicKey key{};
    bool      signedToEnd{};
    uint64_t  verifiedPackets{};
};

// Metadata a converted capture carries about its source.
struct SourceInfo
{
    std::string                 format;
    std::string                 formatVersion;
    uint32_t                    skippedRecords{};
    int32_t                     utcOffsetSeconds{};
    std::array<uint8_t, 64>     sourceHash{};
    std::vector<uint8_t>        metadata;
    std::optional<SourceSigner> signer; // the SOURCE_SIGNER block, when the source was signed
};

struct ReadMarker
{
    MarkerKind  kind;
    std::string text;
};

// Yielded by Reader::next. data and markers reference internal Reader buffers
// and are invalidated by the next call to next, a seek, reset, or destruction.
struct ReadPacket
{
    uint64_t                    timestamp;
    uint8_t                     channel;
    uint16_t                    opcode;
    uint16_t                    flags;
    PacketDirection             direction;
    std::span<const std::byte>  data;
    std::span<const ReadMarker> markers; // markers just before this packet
};

struct ExtensionBlock
{
    uint32_t             type;
    std::vector<uint8_t> data;
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
    PacketTooLarge,
    CompressFailed,
    // Appended only: the bindings mirror this enum by ordinal.
    HeaderChecksumMismatch,
    ExtensionChecksumMismatch,
    MissingPolicy,
    UnknownFrameKind,
    UnknownPacketFlag,
    InvalidPolicy,
    InvalidExtension,
    WriteFailed,
    PacketTooShort,
    TranscodeRefused,
    TranscodeMismatch,
    UnknownRecordingMode,
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
