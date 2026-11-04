#include "xicap/pseudonym.h"
#include "xicap/writer.h"

#include <monocypher.h>

#include <algorithm>
#include <cstring>
#include <vector>

namespace xicap
{
namespace
{

constexpr uint32_t NPC_IDS      = 0x01000000; // NPC and mob ids carry the zone from here up
constexpr uint32_t LOW_ID_BITS  = 0xFFFFF;    // search replies carry these 20 bits of a player id
constexpr uint32_t SWEEP_MIN_ID = 0x10000;    // smaller numbers match too much else to sweep for

constexpr uint8_t GAME   = 0;
constexpr uint8_t SEARCH = 1;
constexpr auto    S2C    = PacketDirection::ServerToClient;
constexpr auto    C2S    = PacketDirection::ClientToServer;

constexpr auto id(uint8_t channel, PacketDirection direction, uint16_t opcode, uint16_t offset, uint8_t count = 1, uint8_t stride = 0) -> PseudonymPlace
{
    return { channel, direction, opcode, offset, PseudonymKind::Id, 4, count, stride, 0, 0, 0 };
}

constexpr auto name(uint8_t channel, PacketDirection direction, uint16_t opcode, uint16_t offset, uint8_t size = 16, uint8_t count = 1, uint8_t stride = 0) -> PseudonymPlace
{
    return { channel, direction, opcode, offset, PseudonymKind::Name, size, count, stride, 0, 0, 0 };
}

constexpr auto signature(uint16_t opcode, uint16_t offset, uint8_t count = 1, uint8_t stride = 0) -> PseudonymPlace
{
    return { GAME, S2C, opcode, offset, PseudonymKind::Signature, 24, count, stride, 0, 0, 0 };
}

constexpr auto when(PseudonymPlace place, uint8_t at, uint16_t mask, uint16_t is) -> PseudonymPlace
{
    place.when = at;
    place.mask = mask;
    place.is   = is;
    return place;
}

// A name that belongs to the id at `id`: rewritten only when that id is a player's, whose top byte is 0. A trust in a
// party list keeps its name.
constexpr auto ofPlayer(PseudonymPlace place, uint8_t id) -> PseudonymPlace
{
    return when(place, static_cast<uint8_t>(id + 2), 0xFF00, 0);
}

// The field map. Offsets count from the packet's first byte: the 4-byte header on the game channel, the size on the
// search channel. Layouts after ffxi-dev/packets (atom0s's XiPackets) and LandSandBoat; pseudonym_fields.tsv says which
// were checked on retail packets. An id field may also hold an NPC's id, which stays. Keep pseudonym_fields.tsv in step,
// and bump anonymousExclusionPolicy's version with every change.
// clang-format off
constexpr PseudonymPlace FIELD_MAP[] = {
    id(GAME, S2C, 0x009, 4),                                   // message: UniqueNo
    id(GAME, S2C, 0x00A, 4), id(GAME, S2C, 0x00A, 44),         // zone-in: UniqueNo, BtTargetID
    name(GAME, S2C, 0x00A, 132),                               //   name
    id(GAME, S2C, 0x00D, 4), id(GAME, S2C, 0x00D, 44),         // PC update: UniqueNo, BtTargetID
    name(GAME, S2C, 0x00D, 90),                                //   name
    id(GAME, S2C, 0x00E, 4), id(GAME, S2C, 0x00E, 44),         // NPC update: UniqueNo, BtTargetID (who it fights)
    id(GAME, S2C, 0x013, 4),                                   // GM command: GMUniqueNo
    id(GAME, S2C, 0x014, 4),                                   // tell: UniqueNo
    name(GAME, S2C, 0x017, 8, 15),                             // chat: sName
    id(GAME, S2C, 0x021, 4), id(GAME, S2C, 0x022, 4),          // trade request and result: UniqueNo
    id(GAME, S2C, 0x027, 4), id(GAME, S2C, 0x02A, 4),          // talk with numbers: UniqueNo
    id(GAME, S2C, 0x029, 4), id(GAME, S2C, 0x029, 8),          // battle message: UniqueNoCas, UniqueNoTar
    id(GAME, S2C, 0x02C, 4),                                   // channel state: UniqueNo
    id(GAME, S2C, 0x02D, 4), id(GAME, S2C, 0x02D, 8),          // battle message 2: UniqueNoCas, UniqueNoTar
    id(GAME, S2C, 0x02F, 4),                                   // dig: TarUniqueNo
    id(GAME, S2C, 0x030, 4), id(GAME, S2C, 0x032, 4),          // effect, event: UniqueNo
    id(GAME, S2C, 0x033, 4), id(GAME, S2C, 0x034, 4),          // event with strings, numbers: UniqueNo
    id(GAME, S2C, 0x036, 4), id(GAME, S2C, 0x03B, 4),          // talk, event message: UniqueNo
    id(GAME, S2C, 0x037, 36),                                  // server status: UniqueNo
    id(GAME, S2C, 0x038, 4), id(GAME, S2C, 0x038, 8),          // scheduler: UniqueNoCas, UniqueNoTar
    id(GAME, S2C, 0x039, 4), id(GAME, S2C, 0x039, 8),          // map scheduler: UniqueNoCas, UniqueNoTar
    id(GAME, S2C, 0x03A, 4), id(GAME, S2C, 0x03A, 8),          // magic scheduler: UniqueNoCas, UniqueNoTar
    id(GAME, S2C, 0x042, 4), name(GAME, S2C, 0x042, 8),        // blacklist edit: ID, Name
    id(GAME, S2C, 0x043, 4), ofPlayer(name(GAME, S2C, 0x043, 16), 4),       // talk with a name: UniqueNo, sName
    name(GAME, S2C, 0x04B, 20),                                // delivery box: State.box_state To or From
    name(GAME, S2C, 0x04C, 24),                                // auction house: Parcel.Name
    id(GAME, S2C, 0x058, 4),                                   // assist: UniqueNo
    id(GAME, S2C, 0x05A, 4), id(GAME, S2C, 0x05A, 8),          // emote: CasUniqueNo, TarUniqueNo
    id(GAME, S2C, 0x05A, 24, 5, 4),                            //   FaithUniqueNo[5]
    id(GAME, S2C, 0x05B, 16), id(GAME, S2C, 0x065, 16),        // positions: UniqueNo
    id(GAME, S2C, 0x067, 8), id(GAME, S2C, 0x068, 8),          // pet and trust updates: UniqueNo
    when(id(GAME, S2C, 0x067, 32), 4, 0x3F, 2),                //   mode 2: UniqueNoMog
    when(id(GAME, S2C, 0x068, 32), 4, 0x3F, 2),                //   mode 2: UniqueNoMog
    when(id(GAME, S2C, 0x067, 20), 4, 0x3F, 4),                //   mode 4: UniqueNoTarget
    when(id(GAME, S2C, 0x068, 20), 4, 0x3F, 4),                //   mode 4: UniqueNoTarget
    name(GAME, S2C, 0x070, 30),                                // synthesis by another player: name
    id(GAME, S2C, 0x076, 4, 5, 48),                            // party effects: Members[5].UniqueNo
    id(GAME, S2C, 0x078, 4), ofPlayer(name(GAME, S2C, 0x078, 14, 15), 4),   // proposal: UniqueNo, sName
    name(GAME, S2C, 0x079, 29, 15),                            // proposal state: sPropName
    id(GAME, S2C, 0x0A0, 4),                                   // party map: UniqueID
    id(GAME, S2C, 0x0B7, 68), name(GAME, S2C, 0x0B7, 72),      // GM item: UniqueNo, sName
    id(GAME, S2C, 0x0C8, 8, 20, 12),                           // alliance: GroupTbl[20].UniqueNo
    id(GAME, S2C, 0x0C9, 4),                                   // check: UniqNo
    when(signature(0x0C9, 16, 16, 28), 10, 0xFF, 3),           //   OptionFlag 3: Equip[16].Data
    name(GAME, S2C, 0x0CA, 128),                               // bazaar message: sName
    name(GAME, S2C, 0x0CC, 140),                               // linkshell message: modifier
    id(GAME, S2C, 0x0D2, 8), id(GAME, S2C, 0x0D2, 32),         // treasure pool: TargetUniqueNo, LootUniqueNo
    ofPlayer(name(GAME, S2C, 0x0D2, 40), 32),                  //   LootActName
    id(GAME, S2C, 0x0D3, 4), id(GAME, S2C, 0x0D3, 8),          // treasure lot: LootUniqueNo, EntryUniqueNo
    ofPlayer(name(GAME, S2C, 0x0D3, 22), 4), ofPlayer(name(GAME, S2C, 0x0D3, 38), 8),    //   sLootName, sLootName2
    id(GAME, S2C, 0x0DC, 4), name(GAME, S2C, 0x0DC, 12),       // party invite: UniqueNo, sName
    id(GAME, S2C, 0x0DD, 4), ofPlayer(name(GAME, S2C, 0x0DD, 40), 4),       // party member: UniqueNo, Name
    id(GAME, S2C, 0x0DF, 4),                                   // party member state: UniqueNo
    id(GAME, S2C, 0x0E2, 4), ofPlayer(name(GAME, S2C, 0x0E2, 40), 4),       // party member 2: UniqueNo, Name
    when(id(GAME, S2C, 0x0E6, 8), 4, 0xFFC0, 3 << 6),          // ballista, mode 3 (scout): RookUniqueNo
    id(GAME, S2C, 0x0F9, 4),                                   // raise: UniqueNo
    signature(0x020, 17), signature(0x023, 14),                // item, trade item: Attr
    signature(0x105, 17),                                      // bazaar item: Attr
    name(GAME, S2C, 0x106, 8), name(GAME, S2C, 0x107, 4),      // bazaar buy and close: sName
    id(GAME, S2C, 0x108, 4), name(GAME, S2C, 0x108, 16),       // bazaar shopper: UniqueNo, sName
    id(GAME, S2C, 0x109, 4), name(GAME, S2C, 0x109, 12),       // bazaar sale: UniqueNo, sName
    name(GAME, S2C, 0x10A, 10),                                // bazaar sold: sName
    id(GAME, S2C, 0x11D, 4), name(GAME, S2C, 0x11D, 12),       // party request: UniqueNo, sName

    id(GAME, C2S, 0x00A, 12), name(GAME, C2S, 0x00A, 34, 15),  // zone-in: UniqueNo, sName
    id(GAME, C2S, 0x017, 8), id(GAME, C2S, 0x017, 12),         // character request: UniqueNo2, UniqueNo3
    id(GAME, C2S, 0x01A, 4),                                   // action: UniqueNo
    id(GAME, C2S, 0x01F, 4),                                   // GM command: GMUniqueNo
    id(GAME, C2S, 0x032, 4), id(GAME, C2S, 0x036, 4),          // trade request, item transfer: UniqueNo
    id(GAME, C2S, 0x037, 4),                                   // item use: UniqueNo
    id(GAME, C2S, 0x03D, 4), name(GAME, C2S, 0x03D, 8),        // blacklist edit: ID, Name
    name(GAME, C2S, 0x04D, 16),                                // delivery box: TargetName
    id(GAME, C2S, 0x05B, 4), id(GAME, C2S, 0x05C, 16),         // event end: UniqueNo
    id(GAME, C2S, 0x05D, 4),                                   // emote: UniqueNo
    id(GAME, C2S, 0x060, 4), id(GAME, C2S, 0x063, 4),          // event password, dig: UniqueNo
    id(GAME, C2S, 0x064, 4),                                   // key item: UniqueNo
    id(GAME, C2S, 0x06E, 4),                                   // party invite: UniqueNo
    id(GAME, C2S, 0x071, 4), name(GAME, C2S, 0x071, 12, 15),   // party kick: UniqueNo, sName
    id(GAME, C2S, 0x073, 4),                                   // party change: UniqueNo
    name(GAME, C2S, 0x077, 4),                                 // party change 2: sName
    name(GAME, C2S, 0x0A1, 5, 15),                             // vote: Name
    name(GAME, C2S, 0x0B6, 6, 15),                             // tell: sName
    name(GAME, C2S, 0x0B7, 6, 15),                             // assist channel: sName
    id(GAME, C2S, 0x0D8, 12),                                  // private dungeon: UniqueNo
    id(GAME, C2S, 0x0DD, 4),                                   // check: UniqueNo
    id(GAME, C2S, 0x0E2, 12),                                  // linkshell message post: uniqNo
    id(GAME, C2S, 0x105, 4),                                   // bazaar open: UniqueNo

    id(SEARCH, C2S, 0x01, 0x12, 20, 4),                        // players by id: the ids
    id(SEARCH, C2S, 0x02, 0x10), id(SEARCH, C2S, 0x02, 0x14),  // party list: party id, alliance id
    id(SEARCH, C2S, 0x08, 0x10),                               // comment request: player id
    name(SEARCH, S2C, 0x85, 0x28, 16, 10, 40),                 // auction history: Name1 of each of 10 sales
    name(SEARCH, S2C, 0x85, 0x38, 16, 10, 40),                 //   Name2
    name(SEARCH, S2C, 0x86, 0x28, 16, 10, 40),                 // auction history of a stack: Name1 of each of 10 sales
    name(SEARCH, S2C, 0x86, 0x38, 16, 10, 40),                 //   Name2
    id(SEARCH, S2C, 0x88, 0x18),                               // comment: player id
};
// clang-format on

constexpr size_t SEARCH_BODY = 0x0C; // after the size, the magic, the length, and the type

auto byteAt(std::span<const std::byte> data, size_t i) -> uint8_t
{
    return std::to_integer<uint8_t>(data[i]);
}

auto u16At(std::span<const std::byte> data, size_t i) -> uint16_t
{
    return static_cast<uint16_t>(byteAt(data, i) | byteAt(data, i + 1) << 8);
}

auto u32At(std::span<const std::byte> data, size_t i) -> uint32_t
{
    return u16At(data, i) | static_cast<uint32_t>(u16At(data, i + 2)) << 16;
}

auto putU32(std::span<std::byte> data, size_t i, uint32_t value) -> void
{
    for (size_t k = 0; k < 4; ++k)
    {
        data[i + k] = static_cast<std::byte>(value >> (8 * k));
    }
}

auto isLetter(uint8_t c) -> bool
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

auto isUpper(uint8_t c) -> bool
{
    return c >= 'A' && c <= 'Z';
}

// Letters only, 1 to 15 of them, as every character name.
auto isName(std::string_view text) -> bool
{
    return !text.empty() && text.size() <= 15 && std::ranges::all_of(text, [](char c)
                                                                     {
                                                                         return isLetter(static_cast<uint8_t>(c));
                                                                     });
}

// Bit fields, least significant bit first (the action packet) or most significant first (the search server's).
struct Bits
{
    std::span<std::byte> data;
    bool                 msbFirst;

    [[nodiscard]] auto size() const -> size_t
    {
        return data.size() * 8;
    }

    [[nodiscard]] auto bit(size_t pos) const -> uint32_t
    {
        const auto shift = msbFirst ? 7 - pos % 8 : pos % 8;
        return (byteAt(data, pos / 8) >> shift) & 1;
    }

    [[nodiscard]] auto get(size_t pos, size_t n) const -> uint32_t
    {
        uint32_t value = 0;
        for (size_t i = 0; i < n; ++i)
        {
            value |= bit(pos + i) << (msbFirst ? n - 1 - i : i);
        }
        return value;
    }

    auto set(size_t pos, size_t n, uint32_t value) const -> void
    {
        for (size_t i = 0; i < n; ++i)
        {
            const auto p     = pos + i;
            const auto shift = msbFirst ? 7 - p % 8 : p % 8;
            const auto v     = (value >> (msbFirst ? n - 1 - i : i)) & 1;
            auto       b     = byteAt(data, p / 8);
            b                = static_cast<uint8_t>((b & ~(1u << shift)) | v << shift);
            data[p / 8]      = static_cast<std::byte>(b);
        }
    }

    auto zero(size_t from, size_t to) const -> void
    {
        for (; from < to; ++from)
        {
            set(from, 1, 0);
        }
    }
};

// Bits after a search reply entry's 5-bit tag, by tag, after LandSandBoat's search server; 0 for a tag not known.
auto replyTagBits(uint32_t tag) -> size_t
{
    switch (tag)
    {
        case 0x01: // zone
        case 0x03: // jobs
            return 10;
        case 0x02: // nation
            return 2;
        case 0x04: // levels
        case 0x06: // flags
        case 0x17: // languages
            return 16;
        case 0x05: // race
            return 4;
        case 0x07: // master level
        case 0x0D: // linkshell rank
        case 0x10: // rank
            return 8;
        case 0x08: // id
            return 20;
        case 0x0A:
        case 0x0B:
        case 0x0C:
        case 0x0E:
        case 0x11:
        case 0x13:
        case 0x14:
        case 0x16:
            return 32;
        default:
            return 0;
    }
}

// Search types this library reads. Any other is zeroed past its type: its layout is not known.
auto searchKnown(uint8_t type) -> bool
{
    switch (type)
    {
        case 0x00: // search all
        case 0x01: // players by id
        case 0x02: // party and linkshell list
        case 0x03: // search
        case 0x05: // auction history
        case 0x06: // auction history of a stack
        case 0x08: // comment
        case 0x10: // auction list, more
        case 0x15: // auction list
            return true;
        default:
            return type >= 0x80 && searchKnown(type & 0x7F);
    }
}

// Replies whose bytes after the length at 0x08 hold the client's hash of the plaintext, which would confirm a guessed name.
auto searchHashed(uint8_t type) -> bool
{
    return (type >= 0x80 && type <= 0x83) || type == 0x85 || type == 0x86 || type == 0x88;
}

auto signatureCode(char c) -> uint32_t
{
    if (c >= '0' && c <= '9')
    {
        return c - '0' + 1;
    }
    if (c >= 'A' && c <= 'Z')
    {
        return c - 'A' + 11;
    }
    return c - 'a' + 37;
}

auto signatureChar(uint32_t code) -> char
{
    if (code >= 1 && code <= 10)
    {
        return static_cast<char>('0' + code - 1);
    }
    if (code >= 11 && code <= 36)
    {
        return static_cast<char>('A' + code - 11);
    }
    if (code >= 37 && code <= 62)
    {
        return static_cast<char>('a' + code - 37);
    }
    return 0;
}

} // namespace

auto pseudonymFieldMap() -> std::span<const PseudonymPlace>
{
    return FIELD_MAP;
}

auto deriveKey(const SecretSeed& seed, std::string_view label) -> std::array<uint8_t, 32>
{
    std::array<uint8_t, 32> out{};
    crypto_blake2b_keyed(out.data(), out.size(), seed.data(), seed.size(), reinterpret_cast<const uint8_t*>(label.data()), label.size());
    return out;
}

auto anonymousExclusionPolicy() -> const ExclusionPolicy&
{
    static const ExclusionPolicy policy = []
    {
        ExclusionPolicy p{ .name = "xicap-anonymous", .version = 2, .rules = defaultExclusionPolicy().rules };
        // Text players write that the default keeps. Only the text: the rest of each packet stays.
        const auto text = [&](uint8_t channel, ExclusionDirection direction, uint16_t opcode, uint32_t offset, uint32_t length)
        {
            p.rules.push_back({ .channel = channel, .direction = direction, .action = ExclusionAction::ZeroRange, .opcode = opcode, .ranges = { { .offset = offset, .length = length } } });
        };
        constexpr uint32_t TO_END = 0xFFFFFFFF;
        text(GAME, ExclusionDirection::ServerToClient, 0x014, 12, TO_END); // tell: Str
        text(GAME, ExclusionDirection::ServerToClient, 0x016, 7, TO_END);  // talk: Str
        text(GAME, ExclusionDirection::ServerToClient, 0x078, 30, TO_END); // proposal: Str
        text(GAME, ExclusionDirection::ServerToClient, 0x079, 44, TO_END); // proposal state: Str
        text(GAME, ExclusionDirection::ServerToClient, 0x0CA, 4, 123);     // bazaar message: sInspectMessage
        text(GAME, ExclusionDirection::ClientToServer, 0x0A0, 5, TO_END);  // proposal: Str
        text(SEARCH, ExclusionDirection::ServerToClient, 0x88, 0x1E, 123); // search comment
        return p;
    }();
    return policy;
}

Pseudonymizer::Pseudonymizer(const PseudonymKey& key)
: key_(key)
{
}

auto Pseudonymizer::name(std::string_view real) -> std::string
{
    std::string text(real);
    if (const auto it = names_.find(text); it != names_.end())
    {
        return it->second;
    }
    std::vector<uint8_t> message{ 'n' };
    message.insert(message.end(), text.begin(), text.end());
    std::array<uint8_t, 64> hash{};
    crypto_blake2b_keyed(hash.data(), hash.size(), key_.data(), key_.size(), message.data(), message.size());
    std::string out(text.size(), 'a');
    for (size_t i = 0; i < out.size(); ++i)
    {
        out[i] = static_cast<char>((i == 0 ? 'A' : 'a') + hash[i % hash.size()] % 26);
    }
    names_.emplace(std::move(text), out);
    return out;
}

// A keyed permutation of the low 20 bits, never giving 0: a 4-round Feistel network, walked past 0.
auto Pseudonymizer::playerId(uint32_t id) -> uint32_t
{
    if (id == 0 || id >= NPC_IDS || (id & LOW_ID_BITS) == 0)
    {
        return id;
    }
    if (const auto it = ids_.find(id); it != ids_.end())
    {
        return it->second;
    }
    uint32_t x = id & LOW_ID_BITS;
    do
    {
        uint32_t left  = x >> 10;
        uint32_t right = x & 0x3FF;
        for (uint8_t round = 0; round < 4; ++round)
        {
            const uint8_t message[] = { 'i', round, static_cast<uint8_t>(right), static_cast<uint8_t>(right >> 8) };
            uint8_t       f[2]{};
            crypto_blake2b_keyed(f, sizeof f, key_.data(), key_.size(), message, sizeof message);
            const uint32_t next = left ^ ((f[0] | f[1] << 8) & 0x3FF);
            left                = right;
            right               = next;
        }
        x = left << 10 | right;
    } while (x == 0);
    const auto out = (id & ~LOW_ID_BITS) | x;
    ids_.emplace(id, out);
    return out;
}

auto Pseudonymizer::contentId(uint32_t id) const -> uint32_t
{
    if (id == 0)
    {
        return 0;
    }
    const uint8_t message[] = { 'c', static_cast<uint8_t>(id), static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id >> 16), static_cast<uint8_t>(id >> 24) };
    uint8_t       hash[4]{};
    crypto_blake2b_keyed(hash, sizeof hash, key_.data(), key_.size(), message, sizeof message);
    return 0x80000000u | hash[0] | hash[1] << 8 | hash[2] << 16 | static_cast<uint32_t>(hash[3] & 0x7F) << 24;
}

auto Pseudonymizer::character(const CharacterIdentity& real) -> CharacterIdentity
{
    auto out        = real;
    out.contentId   = contentId(real.contentId);
    out.characterId = playerId(real.characterId);
    const auto text = std::string_view(real.characterName.data(), strnlen(real.characterName.data(), real.characterName.size()));
    if (!text.empty())
    {
        const auto fake = name(text);
        out.characterName.fill(0);
        std::ranges::copy(fake, out.characterName.begin());
    }
    return out;
}

auto Pseudonymizer::packet(uint8_t channel, PacketDirection direction, std::span<std::byte> data) -> void
{
    if (channel != GAME && channel != SEARCH)
    {
        return; // a channel this library does not define
    }
    const size_t start = channel == GAME ? 4 : SEARCH_BODY;
    if (data.size() <= start)
    {
        return;
    }
    std::vector<bool> done(data.size()); // rewritten bytes, which the sweep leaves alone
    const auto        mark = [&](size_t from, size_t to)
    {
        std::fill(done.begin() + static_cast<ptrdiff_t>(from), done.begin() + static_cast<ptrdiff_t>(std::min(to, data.size())), true);
    };
    const auto zero = [&](size_t from, size_t to)
    {
        to = std::min(to, data.size());
        if (from < to)
        {
            std::fill(data.begin() + static_cast<ptrdiff_t>(from), data.begin() + static_cast<ptrdiff_t>(to), std::byte{ 0 });
            mark(from, to);
        }
    };
    const auto rewriteId = [&](size_t at)
    {
        putU32(data, at, playerId(u32At(data, at)));
        mark(at, at + 4);
    };
    // A name field: rewritten when it holds a name, with the bytes after it zeroed, since they may be what is left of a
    // longer name. Anything else in it stays.
    const auto rewriteName = [&](size_t at, size_t size)
    {
        size              = std::min(size, data.size() - at);
        const auto* first = reinterpret_cast<const char*>(data.data() + at);
        const auto  text  = std::string_view(first, strnlen(first, size));
        if (!isName(text))
        {
            return;
        }
        const auto fake = name(text);
        for (size_t i = 0; i < size; ++i)
        {
            data[at + i] = static_cast<std::byte>(i < fake.size() ? fake[i] : 0);
        }
        mark(at, at + size);
    };
    // Bytes 12 to 23 of an item's extra data, read as 6-bit codes, most significant bit first, ending at a 0.
    const auto rewriteSignature = [&](size_t at)
    {
        const Bits  bits{ data.subspan(at + 12, 12), true };
        std::string text;
        size_t      pos = 0;
        for (; pos + 6 <= bits.size(); pos += 6)
        {
            const auto code = bits.get(pos, 6);
            if (code == 0)
            {
                break;
            }
            text += signatureChar(code);
        }
        for (size_t p = pos; p < bits.size(); ++p)
        {
            if (bits.bit(p) != 0)
            {
                return; // not a signature
            }
        }
        if (text.size() < 3 || !isName(text) || !isUpper(static_cast<uint8_t>(text[0])))
        {
            return;
        }
        const auto fake = name(text);
        for (size_t i = 0; i < fake.size(); ++i)
        {
            bits.set(i * 6, 6, signatureCode(fake[i]));
        }
        mark(at + 12, at + 24);
    };

    const auto opcode = channel == GAME ? static_cast<uint16_t>(u16At(data, 0) & 0x1FF) : std::to_integer<uint16_t>(data[0x0B]);
    for (const auto& place : FIELD_MAP)
    {
        if (place.channel != channel || place.direction != direction || place.opcode != opcode)
        {
            continue;
        }
        if (place.mask != 0 && (place.when + 2u > data.size() || (u16At(data, place.when) & place.mask) != place.is))
        {
            continue;
        }
        for (size_t i = 0; i < place.count; ++i)
        {
            const size_t at = place.offset + i * place.stride;
            switch (place.kind)
            {
                case PseudonymKind::Id:
                    if (at + 4 <= data.size())
                    {
                        rewriteId(at);
                    }
                    break;
                case PseudonymKind::Name:
                    if (at < data.size())
                    {
                        rewriteName(at, place.size);
                    }
                    break;
                case PseudonymKind::Signature:
                    if (at + 24 <= data.size())
                    {
                        rewriteSignature(at);
                    }
                    break;
            }
        }
    }

    // The walkers, for fields at places that depend on the packet. FORMAT.md, Anonymous captures, states each.
    if (channel == GAME && direction == S2C && opcode == 0x028)
    {
        // Action: the actor at bit 40, a 6-bit target count at bit 72, and from bit 150 each target's 32-bit id, a 4-bit
        // result count, and per result 85 bits, a flag with 37 more, and a flag with 34 more. Least significant bit first.
        const Bits bits{ data, false };
        const auto rewriteBits = [&](size_t pos)
        {
            bits.set(pos, 32, playerId(bits.get(pos, 32)));
            mark(pos / 8, (pos + 39) / 8);
        };
        if (bits.size() >= 72)
        {
            rewriteBits(40);
            const auto targets = bits.get(72, 6);
            size_t     pos     = 72 + 6 + 4 + 4 + 32 + 32;
            for (uint32_t t = 0; t < targets && pos + 36 <= bits.size(); ++t)
            {
                rewriteBits(pos);
                const auto results = bits.get(pos + 32, 4);
                pos += 36;
                for (uint32_t r = 0; r < results && pos + 87 <= bits.size(); ++r)
                {
                    pos += 85;
                    pos += bits.get(pos, 1) ? 1 + 37 : 1;
                    if (pos >= bits.size())
                    {
                        break;
                    }
                    pos += bits.get(pos, 1) ? 1 + 34 : 1;
                }
            }
        }
    }
    else if (channel == GAME && direction == C2S && opcode == 0x0D3 && data.size() >= 8)
    {
        // Call for a GM: byte 7 counts the blocks from byte 8, each a type, its length counting this 4-byte header, and
        // 2 bytes. A string block (3) is "KEY:value": the value is what the player typed unless the key starts with
        // GENERIC., GAME. or EXEC., and is zeroed. A lobby block (4) holds 28-byte entries: an id at 8 and a name at 12.
        // Blocks 0 to 2 hold numbers; any other type is zeroed, as is anything past a block that does not fit.
        size_t at = 8;
        for (uint8_t b = 0; b < byteAt(data, 7) && at < data.size(); ++b)
        {
            const auto type   = at + 4 <= data.size() ? byteAt(data, at) : 0xFF;
            const auto length = at + 4 <= data.size() ? byteAt(data, at + 1) : 0;
            if (length < 4 || at + length > data.size())
            {
                zero(at, data.size());
                break;
            }
            const auto body = at + 4;
            const auto end  = at + length;
            if (type == 3)
            {
                const auto* text  = reinterpret_cast<const char*>(data.data() + body);
                const auto  value = std::string_view(text, end - body);
                const auto  colon = value.find(':');
                const auto  key   = value.substr(0, colon == std::string_view::npos ? 0 : colon);
                if (!key.starts_with("GENERIC.") && !key.starts_with("GAME.") && !key.starts_with("EXEC."))
                {
                    zero(colon == std::string_view::npos ? body : body + colon + 1, end);
                }
            }
            else if (type == 4)
            {
                for (size_t e = body; e + 28 <= end; e += 28)
                {
                    const auto ident = u32At(data, e + 8);
                    putU32(data, e + 8, ident < NPC_IDS ? playerId(ident) : contentId(ident));
                    mark(e + 8, e + 12);
                    rewriteName(e + 12, 16);
                }
            }
            else if (type > 4)
            {
                zero(body, end);
            }
            at = end;
        }
    }
    else if (channel == SEARCH)
    {
        const auto type = byteAt(data, 0x0B);
        const Bits bits{ data, true };
        if (!searchKnown(type))
        {
            zero(SEARCH_BODY, data.size());
            return;
        }
        if (direction == C2S && (type == 0x00 || type == 0x03) && data.size() > 0x11)
        {
            // A search: from byte 0x11, as many bytes as byte 0x10 says, of 5-bit tags. Most tags then have a sort bit
            // and a presence bit; a present name is a 5-bit length and 7-bit characters. A tag not known is zeroed
            // from it on, as LandSandBoat's server reads them.
            const size_t first = 0x11 * 8;
            const size_t stop  = std::min(data.size(), size_t{ 0x11 } + byteAt(data, 0x10)) * 8;
            for (size_t pos = first; pos + 5 < stop;)
            {
                const auto tag   = bits.get(pos, 5);
                const auto tagAt = pos;
                pos += 5;
                const bool flagged = tag != 0x0C && tag != 0x18 && tag != 0x0B && tag != 0x13 && tag != 0x14 && tag != 0x11 && tag != 0x16;
                bool       present = true;
                if (flagged)
                {
                    if (pos + 3 >= stop)
                    {
                        break;
                    }
                    present = bits.get(pos + 1, 1) != 0;
                    pos += 2;
                }
                size_t n = 0;
                switch (tag)
                {
                    case 0x00: // name
                        if (present)
                        {
                            if (pos + 5 >= stop)
                            {
                                pos = stop;
                                break;
                            }
                            const auto length = bits.get(pos, 5);
                            pos += 5;
                            if (pos + length * 7 > stop)
                            {
                                bits.zero(pos, stop);
                                pos = stop;
                                break;
                            }
                            std::string text;
                            for (uint32_t i = 0; i < length; ++i)
                            {
                                text += static_cast<char>(bits.get(pos + i * 7, 7));
                            }
                            if (isName(text))
                            {
                                const auto fake = name(text);
                                for (uint32_t i = 0; i < length; ++i)
                                {
                                    bits.set(pos + i * 7, 7, static_cast<uint8_t>(fake[i]));
                                }
                            }
                            else
                            {
                                bits.zero(pos, pos + length * 7);
                            }
                            pos += length * 7;
                        }
                        break;
                    case 0x01:
                        n = present ? 10 : 0;
                        break; // zone
                    case 0x02:
                        n = present ? 2 : 0;
                        break; // nation
                    case 0x03:
                        n = present ? 5 : 0;
                        break; // job
                    case 0x04: // levels
                    case 0x07: // master levels
                    case 0x10: // ranks
                    case 0x06:
                        n = present ? 16 : 0;
                        break; // flags
                    case 0x05:
                        n = present ? 4 : 0;
                        break; // race
                    case 0x0B: // linkshells
                    case 0x13:
                    case 0x14:
                    case 0x11: // comment type
                    case 0x16:
                        n = 32;
                        break; // flags
                    case 0x0C: // friends
                    case 0x18:
                        n = 0;
                        break; // party requests
                    default:
                        bits.zero(tagAt, stop);
                        pos = stop;
                        break;
                }
                pos += n;
            }
            mark(0x11, stop / 8);
        }
        else if (direction == S2C && type >= 0x80 && type <= 0x83 && data.size() >= 0x18)
        {
            // Players: entries from 0x18 to the length at 0x08, each a size byte and then tagged fields. A name is a
            // 4-bit length and 7-bit characters; an id is 20 bits. An entry with a tag not known is zeroed from it on.
            const auto end = std::min<size_t>(data.size(), u16At(data, 8));
            for (size_t at = 0x18; at < end;)
            {
                const auto   last = std::min(end, at + 1 + byteAt(data, at));
                const size_t stop = last * 8;
                size_t       pos  = (at + 1) * 8;
                while (pos + 5 <= stop)
                {
                    const auto tag = bits.get(pos, 5);
                    pos += 5;
                    if (tag == 0x00)
                    {
                        if (pos + 4 > stop)
                        {
                            break;
                        }
                        const auto length = bits.get(pos, 4);
                        pos += 4;
                        if (pos + length * 7 > stop)
                        {
                            break; // the padding after the last field
                        }
                        std::string text;
                        for (uint32_t i = 0; i < length; ++i)
                        {
                            text += static_cast<char>(bits.get(pos + i * 7, 7));
                        }
                        if (isName(text))
                        {
                            const auto fake = name(text);
                            for (uint32_t i = 0; i < length; ++i)
                            {
                                bits.set(pos + i * 7, 7, static_cast<uint8_t>(fake[i]));
                            }
                        }
                        pos += length * 7;
                    }
                    else if (tag == 0x08 && pos + 20 <= stop)
                    {
                        bits.set(pos, 20, playerId(bits.get(pos, 20)) & LOW_ID_BITS);
                        pos += 20;
                    }
                    else if (const auto n = replyTagBits(tag); n != 0 && pos + n <= stop)
                    {
                        pos += n;
                    }
                    else
                    {
                        bits.zero(pos, stop);
                        pos = stop;
                    }
                }
                mark(at, last);
                at = last;
            }
        }
        if (direction == S2C && searchHashed(type) && data.size() >= 0x0A)
        {
            zero(std::max<size_t>(SEARCH_BODY, u16At(data, 8)), data.size());
        }
    }

    // The sweep: every real name and id met so far, wherever else it sits. A name stands alone, between non-letters.
    for (size_t i = start; i < data.size();)
    {
        if (done[i] || !isUpper(byteAt(data, i)) || isLetter(byteAt(data, i - 1)))
        {
            ++i;
            continue;
        }
        size_t j = i + 1;
        while (j < data.size() && j - i < 16 && isLetter(byteAt(data, j)) && !done[j])
        {
            ++j;
        }
        const auto length = j - i;
        if (length >= 3 && length <= 15 && (j == data.size() || !isLetter(byteAt(data, j))))
        {
            const auto it = names_.find(std::string(reinterpret_cast<const char*>(data.data() + i), length));
            if (it != names_.end())
            {
                std::memcpy(data.data() + i, it->second.data(), length);
                mark(i, j);
            }
        }
        i = j;
    }
    // Ids at any byte, as little-endian u32s. In 0x062, at any bit, least significant first: retail leaves what is left
    // of an action packet's bit stream there. Every bit everywhere would also hit positions, prices and flags that
    // happen to equal an id.
    const Bits   bits{ data, false };
    const size_t step = channel == GAME && direction == S2C && opcode == 0x062 ? 1 : 8;
    for (size_t pos = start * 8; pos + 32 <= bits.size(); pos += step)
    {
        const auto first = pos / 8;
        const auto last  = (pos + 31) / 8;
        if (std::any_of(done.begin() + static_cast<ptrdiff_t>(first), done.begin() + static_cast<ptrdiff_t>(last) + 1, [](bool b)
                        {
                            return b;
                        }))
        {
            continue;
        }
        const auto value = pos % 8 == 0 ? u32At(data, first) : bits.get(pos, 32);
        if (value < SWEEP_MIN_ID || value >= NPC_IDS)
        {
            continue;
        }
        if (const auto it = ids_.find(value); it != ids_.end())
        {
            bits.set(pos, 32, it->second);
            mark(first, last + 1);
            pos += 32 - step;
        }
    }
}

} // namespace xicap
