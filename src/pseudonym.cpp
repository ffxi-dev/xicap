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

enum class Kind : uint8_t
{
    Id,        // u32, little-endian
    Name,      // text of `size` bytes, NUL-padded
    Signature, // an item's 24-byte extra data, whose bytes 12 to 23 may hold a crafter's name in 6-bit codes
};

// A field holding a player's id or name: `count` of them, `stride` bytes apart. With `mask` set, only when byte `when`
// of the packet, masked, equals `is`. A field past the packet's end is skipped.
struct Place
{
    PacketDirection direction;
    uint16_t        opcode;
    uint16_t        offset;
    Kind            kind;
    uint8_t         size   = 0;
    uint8_t         count  = 1;
    uint8_t         stride = 0;
    uint8_t         when   = 0;
    uint8_t         mask   = 0;
    uint8_t         is     = 0;
};

constexpr auto S2C = PacketDirection::ServerToClient;
constexpr auto C2S = PacketDirection::ClientToServer;

constexpr auto id(PacketDirection direction, uint16_t opcode, uint16_t offset, uint8_t count = 1, uint8_t stride = 0) -> Place
{
    return { .direction = direction, .opcode = opcode, .offset = offset, .kind = Kind::Id, .count = count, .stride = stride };
}

constexpr auto name(PacketDirection direction, uint16_t opcode, uint16_t offset, uint8_t size = 16, uint8_t count = 1, uint8_t stride = 0) -> Place
{
    return { .direction = direction, .opcode = opcode, .offset = offset, .kind = Kind::Name, .size = size, .count = count, .stride = stride };
}

constexpr auto signature(uint16_t opcode, uint16_t offset, uint8_t count = 1, uint8_t stride = 0) -> Place
{
    return { .direction = S2C, .opcode = opcode, .offset = offset, .kind = Kind::Signature, .count = count, .stride = stride };
}

constexpr auto when(Place place, uint8_t byte, uint8_t mask, uint8_t is) -> Place
{
    place.when = byte;
    place.mask = mask;
    place.is   = is;
    return place;
}

// The field map: offsets count from the packet's 4-byte header, after ffxi-dev/packets' layouts (atom0s's XiPackets),
// each checked on retail packets from public Mogsafe captures where any were found. An id field may also hold an NPC's
// id, which passes unchanged. Bump anonymousExclusionPolicy's version with every change.
constexpr Place FIELD_MAP[] = {
    id(S2C, 0x009, 4), // message: UniqueNo
    id(S2C, 0x00A, 4),
    id(S2C, 0x00A, 44),    // zone-in: UniqueNo, BtTargetID
    name(S2C, 0x00A, 132), //   name
    id(S2C, 0x00D, 4),
    id(S2C, 0x00D, 44),   // PC update: UniqueNo, BtTargetID
    name(S2C, 0x00D, 90), //   name
    id(S2C, 0x00E, 4),
    id(S2C, 0x00E, 44), // NPC update: UniqueNo, BtTargetID (who it fights)
    id(S2C, 0x013, 4),  // GM command: GMUniqueNo
    id(S2C, 0x021, 4),
    id(S2C, 0x022, 4), // trade request and result: UniqueNo
    id(S2C, 0x027, 4),
    id(S2C, 0x02A, 4), // talk with numbers: UniqueNo
    id(S2C, 0x029, 4),
    id(S2C, 0x029, 8), // battle message: UniqueNoCas, UniqueNoTar
    id(S2C, 0x02C, 4), // channel state: UniqueNo
    id(S2C, 0x02D, 4),
    id(S2C, 0x02D, 8), // battle message 2: UniqueNoCas, UniqueNoTar
    id(S2C, 0x02F, 4), // dig: TarUniqueNo
    id(S2C, 0x030, 4),
    id(S2C, 0x032, 4), // effect, event: UniqueNo
    id(S2C, 0x033, 4),
    id(S2C, 0x034, 4), // event with strings, numbers: UniqueNo
    id(S2C, 0x036, 4),
    id(S2C, 0x03B, 4),  // talk, event message: UniqueNo
    id(S2C, 0x037, 36), // server status: UniqueNo
    id(S2C, 0x038, 4),
    id(S2C, 0x038, 8), // schedulers: UniqueNoCas, UniqueNoTar
    id(S2C, 0x039, 4),
    id(S2C, 0x039, 8), //
    id(S2C, 0x03A, 4),
    id(S2C, 0x03A, 8),               //
    id(S2C, 0x041, 4, 12, 20),       // blacklist: 12 of ID, Name
    name(S2C, 0x041, 8, 16, 12, 20), //
    id(S2C, 0x042, 4),
    name(S2C, 0x042, 8), // blacklist edit: ID, Name
    id(S2C, 0x043, 4),
    name(S2C, 0x043, 16), // talk with a name: UniqueNo, sName
    name(S2C, 0x04B, 20), // delivery box: the sender or recipient of a box slot
    name(S2C, 0x04C, 24), // auction house: Parcel.Name
    id(S2C, 0x058, 4),    // assist: UniqueNo
    id(S2C, 0x05A, 4),
    id(S2C, 0x05A, 8),        // emote: CasUniqueNo, TarUniqueNo
    id(S2C, 0x05A, 24, 5, 4), //   FaithUniqueNo
    id(S2C, 0x05B, 16),
    id(S2C, 0x065, 16), // positions: UniqueNo
    id(S2C, 0x067, 8),
    id(S2C, 0x068, 8),                    // pet and trust updates: UniqueNo
    when(id(S2C, 0x067, 32), 4, 0x3F, 2), //   mode 2: UniqueNoMog
    when(id(S2C, 0x068, 32), 4, 0x3F, 2), //
    when(id(S2C, 0x067, 20), 4, 0x3F, 4), //   mode 4: UniqueNoTarget
    when(id(S2C, 0x068, 20), 4, 0x3F, 4), //
    name(S2C, 0x070, 30),                 // synthesis by another player: name
    id(S2C, 0x076, 4, 5, 48),             // party effects: Members[5].UniqueNo
    id(S2C, 0x0A0, 4),                    // party map: UniqueID
    id(S2C, 0x0B7, 68),
    name(S2C, 0x0B7, 72),                            // GM item: UniqueNo, sName
    id(S2C, 0x0C8, 8, 20, 12),                       // alliance: GroupTbl[20].UniqueNo
    id(S2C, 0x0C9, 4),                               // check: UniqNo
    when(signature(0x0C9, 16, 16, 28), 10, 0xFF, 3), //   OptionFlag 3: Equip[16].Data
    name(S2C, 0x0CA, 128),                           // bazaar message: sName
    id(S2C, 0x0D2, 8),
    id(S2C, 0x0D2, 32),   // treasure pool: TargetUniqueNo, LootUniqueNo
    name(S2C, 0x0D2, 40), //   LootActName
    id(S2C, 0x0D3, 4),
    id(S2C, 0x0D3, 8), // treasure lot: LootUniqueNo, EntryUniqueNo
    name(S2C, 0x0D3, 22),
    name(S2C, 0x0D3, 38), //   sLootName, sLootName2
    id(S2C, 0x0DC, 4),
    name(S2C, 0x0DC, 12), // party invite: UniqueNo, sName
    id(S2C, 0x0DD, 4),
    name(S2C, 0x0DD, 40), // party member: UniqueNo, Name
    id(S2C, 0x0DF, 4),    // party member state: UniqueNo
    id(S2C, 0x0E2, 4),
    name(S2C, 0x0E2, 40), // party member 2: UniqueNo, Name
    id(S2C, 0x0F9, 4),    // raise: UniqueNo
    signature(0x020, 17),
    signature(0x023, 14), // item, trade item: Attr
    signature(0x105, 17), // bazaar item: Attr
    name(S2C, 0x106, 8),
    name(S2C, 0x107, 4), // bazaar buy and close: sName
    id(S2C, 0x108, 4),
    name(S2C, 0x108, 16), // bazaar shopper: UniqueNo, sName
    id(S2C, 0x109, 4),
    name(S2C, 0x109, 12), // bazaar sale: UniqueNo, sName
    name(S2C, 0x10A, 10), // bazaar sold: sName
    id(S2C, 0x11D, 4),
    name(S2C, 0x11D, 12), // party request: UniqueNo, sName

    id(C2S, 0x00A, 12),
    name(C2S, 0x00A, 34, 15), // zone-in: UniqueNo, sName
    id(C2S, 0x017, 8),
    id(C2S, 0x017, 12), // character request: UniqueNo2, UniqueNo3
    id(C2S, 0x01A, 4),  // action: UniqueNo
    id(C2S, 0x01F, 4),  // GM command: GMUniqueNo
    id(C2S, 0x032, 4),
    id(C2S, 0x036, 4), // trade request, item transfer: UniqueNo
    id(C2S, 0x037, 4), // item use: UniqueNo
    id(C2S, 0x03D, 4),
    name(C2S, 0x03D, 8),  // blacklist edit: ID, Name
    name(C2S, 0x04D, 16), // delivery box: TargetName
    id(C2S, 0x05B, 4),
    id(C2S, 0x05C, 16), // event end: UniqueNo
    id(C2S, 0x05D, 4),  // emote: UniqueNo
    id(C2S, 0x060, 4),
    id(C2S, 0x063, 4), // event password, dig: UniqueNo
    id(C2S, 0x064, 4), // key item: UniqueNo
    id(C2S, 0x06E, 4), // party invite: UniqueNo
    id(C2S, 0x071, 4),
    name(C2S, 0x071, 12, 15), // party kick: UniqueNo, sName
    id(C2S, 0x073, 4),        // party change: UniqueNo
    name(C2S, 0x077, 4),      // party change 2: sName
    id(C2S, 0x0D8, 12),       // private dungeon: UniqueNo
    id(C2S, 0x0DD, 4),        // check: UniqueNo
    id(C2S, 0x105, 4),        // bazaar open: UniqueNo
};

auto byteAt(std::span<const std::byte> data, size_t i) -> uint8_t
{
    return std::to_integer<uint8_t>(data[i]);
}

auto u32At(std::span<const std::byte> data, size_t i) -> uint32_t
{
    return byteAt(data, i) | byteAt(data, i + 1) << 8 | byteAt(data, i + 2) << 16 | static_cast<uint32_t>(byteAt(data, i + 3)) << 24;
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

// Bit fields, least significant bit first (the action packet) or most significant first (search replies).
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
};

// Bits after a search reply entry's 5-bit tag, by tag, after LandSandBoat's search server; 0 for a tag not known.
auto searchTagBits(uint32_t tag) -> size_t
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

// Search request types kept as they are: the auction house's item lists name no one.
auto searchKept(uint8_t type) -> bool
{
    return type == 0x10 || type == 0x15 || type == 0x90 || type == 0x95;
}

constexpr size_t SEARCH_BODY = 0x0C; // after the size, the magic, the length, and the type

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
        ExclusionPolicy p{ .name = "xicap-anonymous", .version = 1, .rules = defaultExclusionPolicy().rules };
        const auto      stub = [&](ExclusionDirection direction, uint16_t opcode)
        {
            p.rules.push_back({ .channel = 0, .direction = direction, .action = ExclusionAction::Stub, .opcode = opcode, .ranges = {} });
        };
        // Free text players write, or names at places the field map does not know.
        stub(ExclusionDirection::ServerToClient, 0x014); // tell status, with text
        stub(ExclusionDirection::ServerToClient, 0x016); // talk, with text
        stub(ExclusionDirection::ServerToClient, 0x048); // linkshell concierge
        stub(ExclusionDirection::ServerToClient, 0x078); // proposal start: sName, Str
        stub(ExclusionDirection::ServerToClient, 0x079); // proposal: Str
        stub(ExclusionDirection::ServerToClient, 0x0E6); // ballista: Data
        stub(ExclusionDirection::ClientToServer, 0x0A0); // proposal: Str
        stub(ExclusionDirection::ClientToServer, 0x0A1); // vote: Name
        stub(ExclusionDirection::ClientToServer, 0x0B7); // assist channel: sName, Mes
        stub(ExclusionDirection::ClientToServer, 0x0D3); // call for a GM: Data
        // Search types that name players in layouts not confirmed on retail packets: a search, a party or linkshell list,
        // a comment, and the auction house's sale history. The pseudonymizer zeroes any other type it does not read.
        for (const uint16_t type : { 0x00, 0x02, 0x03, 0x05, 0x06, 0x08, 0x80, 0x82, 0x83, 0x85, 0x86, 0x88 })
        {
            p.rules.push_back({ .channel   = static_cast<uint8_t>(Channel::Search),
                                .direction = ExclusionDirection::Both,
                                .action    = ExclusionAction::ZeroRange,
                                .opcode    = type,
                                .ranges    = { { .offset = SEARCH_BODY, .length = 0xFFFFFFFF } } });
        }
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
    std::vector<bool> done(data.size()); // rewritten bytes, which the sweep leaves alone
    const auto        mark = [&](size_t from, size_t to)
    {
        std::fill(done.begin() + static_cast<ptrdiff_t>(from), done.begin() + static_cast<ptrdiff_t>(to), true);
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

    size_t sweepFrom = 4;
    if (channel == static_cast<uint8_t>(Channel::Game))
    {
        if (data.size() < 4)
        {
            return;
        }
        const auto opcode = static_cast<uint16_t>((byteAt(data, 0) | byteAt(data, 1) << 8) & 0x1FF);
        for (const auto& place : FIELD_MAP)
        {
            if (place.direction != direction || place.opcode != opcode)
            {
                continue;
            }
            if (place.mask != 0 && (place.when >= data.size() || (byteAt(data, place.when) & place.mask) != place.is))
            {
                continue;
            }
            for (size_t i = 0; i < place.count; ++i)
            {
                const size_t at = place.offset + i * place.stride;
                switch (place.kind)
                {
                    case Kind::Id:
                        if (at + 4 <= data.size())
                        {
                            rewriteId(at);
                        }
                        break;
                    case Kind::Name:
                        if (at < data.size())
                        {
                            rewriteName(at, place.size);
                        }
                        break;
                    case Kind::Signature:
                        if (at + 24 <= data.size())
                        {
                            rewriteSignature(at);
                        }
                        break;
                }
            }
        }
        // The action packet's actor and targets sit in a bit stream: the walk follows ffxi-dev/packets' decoder.
        if (direction == S2C && opcode == 0x028)
        {
            const Bits bits{ data, false };
            const auto rewriteBits = [&](size_t pos)
            {
                bits.set(pos, 32, playerId(bits.get(pos, 32)));
                mark(pos / 8, std::min(data.size(), (pos + 39) / 8));
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
    }
    else if (channel == static_cast<uint8_t>(Channel::Search))
    {
        sweepFrom = SEARCH_BODY;
        if (data.size() <= SEARCH_BODY)
        {
            return;
        }
        const auto type = byteAt(data, 0x0B);
        if (type == 0x01 && direction == C2S && data.size() >= 0x12)
        {
            // A request for the players with these ids: a count, then the ids.
            const size_t count = byteAt(data, 0x10) | byteAt(data, 0x11) << 8;
            for (size_t i = 0; i < count && 0x12 + i * 4 + 4 <= data.size(); ++i)
            {
                rewriteId(0x12 + i * 4);
            }
        }
        else if (type == 0x81 && direction == S2C && data.size() >= 0x18)
        {
            // The reply: entries from 0x18 to the length at 0x08, each a size byte and then tagged fields. A name is a
            // 4-bit length and 7-bit characters; an id is 20 bits. An entry with a tag not known is zeroed from it on.
            const auto end = std::min<size_t>(data.size(), byteAt(data, 8) | byteAt(data, 9) << 8);
            const Bits bits{ data, true };
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
                    else if (const auto n = searchTagBits(tag); n != 0 && pos + n <= stop)
                    {
                        pos += n;
                    }
                    else
                    {
                        for (; pos < stop; ++pos)
                        {
                            bits.set(pos, 1, 0);
                        }
                    }
                }
                mark(at, last);
                at = last;
            }
            // After the entries: the client's hash of the plaintext, which would confirm a guessed name, and stale bytes.
            std::fill(data.begin() + static_cast<ptrdiff_t>(end), data.end(), std::byte{ 0 });
            mark(end, data.size());
        }
        else if (!searchKept(type))
        {
            std::fill(data.begin() + SEARCH_BODY, data.end(), std::byte{ 0 });
            return;
        }
    }
    else
    {
        return; // a channel this library does not define
    }

    // The sweep: every real name and id met so far, wherever else it sits. A name stands alone, between non-letters.
    for (size_t i = sweepFrom; i < data.size();)
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
    // Ids at any bit, least significant first: the bytes retail leaves in a packet may be what is left of an action
    // packet's bit stream. Byte-aligned, this reads a little-endian u32.
    const Bits bits{ data, false };
    for (size_t pos = sweepFrom * 8; pos + 32 <= bits.size(); ++pos)
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
            pos += 31;
        }
    }
}

} // namespace xicap
