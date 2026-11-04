#include "helpers.h"

#include <xicap/pseudonym.h>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <fstream>
#include <map>
#include <ranges>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace test;

namespace
{

struct CorpusPacket
{
    uint8_t                channel{};
    PacketDirection        direction{};
    std::vector<std::byte> data;
};

struct Corpus
{
    std::vector<CorpusPacket> packets;
    std::vector<std::string>  names; // every real player name the packets hold
    std::vector<uint32_t>     ids;   // and every real player id
};

auto corpus() -> const Corpus&
{
    static const Corpus c = []
    {
        Corpus        out;
        std::ifstream in(XICAP_PSEUDONYM_CORPUS);
        REQUIRE(in);
        std::string line;
        while (std::getline(in, line))
        {
            std::istringstream words(line);
            std::string        first;
            words >> first;
            if (first == "name")
            {
                words >> out.names.emplace_back();
            }
            else if (first == "id")
            {
                words >> out.ids.emplace_back();
            }
            else if (first == "0" || first == "1")
            {
                int         direction = 0;
                std::string hex;
                words >> direction >> hex;
                CorpusPacket p{ static_cast<uint8_t>(std::stoi(first)), static_cast<PacketDirection>(direction), {} };
                for (size_t i = 0; i + 1 < hex.size(); i += 2)
                {
                    p.data.push_back(static_cast<std::byte>(std::stoi(hex.substr(i, 2), nullptr, 16)));
                }
                out.packets.push_back(std::move(p));
            }
        }
        return out;
    }();
    return c;
}

const PseudonymKey KEY = deriveKey(seed(), PSEUDONYM_KEY_LABEL);

auto u32(std::span<const std::byte> d, size_t i) -> uint32_t
{
    uint32_t v = 0;
    for (size_t k = 0; k < 4; ++k)
    {
        v |= std::to_integer<uint32_t>(d[i + k]) << (8 * k);
    }
    return v;
}

auto text(std::span<const std::byte> d, size_t at, size_t size) -> std::string
{
    std::string out;
    for (size_t i = at; i < std::min(d.size(), at + size) && d[i] != std::byte{ 0 }; ++i)
    {
        out += static_cast<char>(d[i]);
    }
    return out;
}

auto isName(const std::string& s) -> bool
{
    return !s.empty() && s.size() <= 15 && std::ranges::all_of(s, [](char c)
                                                               {
                                                                   return std::isalpha(static_cast<unsigned char>(c)) != 0;
                                                               });
}

auto isPlayer(uint32_t id) -> bool
{
    return id != 0 && id < 0x01000000 && (id & 0xFFFFF) != 0;
}

auto bitsOf(std::span<const std::byte> d, size_t pos, size_t n, bool msbFirst) -> uint32_t
{
    uint32_t v = 0;
    for (size_t i = 0; i < n; ++i)
    {
        const auto p     = pos + i;
        const auto shift = msbFirst ? 7 - p % 8 : p % 8;
        const auto bit   = (std::to_integer<uint32_t>(d[p / 8]) >> shift) & 1;
        v |= bit << (msbFirst ? n - 1 - i : i);
    }
    return v;
}

// What should change in each game packet, stated apart from the library's field map: offset, then 4 for an id, 15 or 16
// for a name, 24 for an item's extra data. A mode of 0 applies always; otherwise only when byte 4's low 6 bits equal it.
struct Expected
{
    uint16_t offset;
    uint8_t  size;
    uint8_t  mode = 0;
};

const std::map<std::pair<PacketDirection, uint16_t>, std::vector<Expected>> EXPECTED{
    { { PacketDirection::ServerToClient, 0x00A }, { { 4, 4 }, { 44, 4 }, { 132, 16 } } },
    { { PacketDirection::ServerToClient, 0x00D }, { { 4, 4 }, { 44, 4 }, { 90, 16 } } },
    { { PacketDirection::ServerToClient, 0x00E }, { { 4, 4 }, { 44, 4 } } },
    { { PacketDirection::ServerToClient, 0x020 }, { { 17, 24 } } },
    { { PacketDirection::ServerToClient, 0x029 }, { { 4, 4 }, { 8, 4 } } },
    { { PacketDirection::ServerToClient, 0x02A }, { { 4, 4 } } },
    { { PacketDirection::ServerToClient, 0x02D }, { { 4, 4 }, { 8, 4 } } },
    { { PacketDirection::ServerToClient, 0x032 }, { { 4, 4 } } },
    { { PacketDirection::ServerToClient, 0x034 }, { { 4, 4 } } },
    { { PacketDirection::ServerToClient, 0x036 }, { { 4, 4 } } },
    { { PacketDirection::ServerToClient, 0x037 }, { { 36, 4 } } },
    { { PacketDirection::ServerToClient, 0x038 }, { { 4, 4 }, { 8, 4 } } },
    { { PacketDirection::ServerToClient, 0x04C }, { { 24, 16 } } },
    { { PacketDirection::ServerToClient, 0x058 }, { { 4, 4 } } },
    { { PacketDirection::ServerToClient, 0x05B }, { { 16, 4 } } },
    { { PacketDirection::ServerToClient, 0x065 }, { { 16, 4 } } },
    { { PacketDirection::ServerToClient, 0x067 }, { { 8, 4 }, { 32, 4, 2 }, { 20, 4, 4 } } },
    { { PacketDirection::ServerToClient, 0x068 }, { { 8, 4 }, { 32, 4, 2 }, { 20, 4, 4 } } },
    { { PacketDirection::ServerToClient, 0x076 }, { { 4, 4 }, { 52, 4 }, { 100, 4 }, { 148, 4 }, { 196, 4 } } },
    { { PacketDirection::ServerToClient, 0x0C8 }, { { 8, 4 }, { 20, 4 }, { 32, 4 }, { 44, 4 }, { 56, 4 }, { 68, 4 }, { 80, 4 }, { 92, 4 }, { 104, 4 }, { 116, 4 }, { 128, 4 }, { 140, 4 }, { 152, 4 }, { 164, 4 }, { 176, 4 }, { 188, 4 }, { 200, 4 }, { 212, 4 }, { 224, 4 }, { 236, 4 } } },
    { { PacketDirection::ServerToClient, 0x0C9 }, { { 4, 4 } } },
    { { PacketDirection::ServerToClient, 0x0CA }, { { 128, 16 } } },
    { { PacketDirection::ServerToClient, 0x0D3 }, { { 4, 4 }, { 8, 4 }, { 22, 16 }, { 38, 16 } } },
    { { PacketDirection::ServerToClient, 0x0DC }, { { 4, 4 }, { 12, 16 } } },
    { { PacketDirection::ServerToClient, 0x0DD }, { { 4, 4 }, { 40, 16 } } },
    { { PacketDirection::ServerToClient, 0x0DF }, { { 4, 4 } } },
    { { PacketDirection::ServerToClient, 0x0E2 }, { { 4, 4 }, { 40, 16 } } },
    { { PacketDirection::ClientToServer, 0x00A }, { { 12, 4 }, { 34, 15 } } },
    { { PacketDirection::ClientToServer, 0x017 }, { { 8, 4 }, { 12, 4 } } },
    { { PacketDirection::ClientToServer, 0x01A }, { { 4, 4 } } },
    { { PacketDirection::ClientToServer, 0x037 }, { { 4, 4 } } },
    { { PacketDirection::ClientToServer, 0x05B }, { { 4, 4 } } },
    { { PacketDirection::ClientToServer, 0x05C }, { { 16, 4 } } },
    { { PacketDirection::ClientToServer, 0x0DD }, { { 4, 4 } } },
    { { PacketDirection::ClientToServer, 0x105 }, { { 4, 4 } } },
};

auto opcodeOf(std::span<const std::byte> d) -> uint16_t
{
    return static_cast<uint16_t>((std::to_integer<uint16_t>(d[0]) | std::to_integer<uint16_t>(d[1]) << 8) & 0x1FF);
}

auto pseudonymized(Pseudonymizer& p, const CorpusPacket& in) -> std::vector<std::byte>
{
    auto out = in.data;
    p.packet(in.channel, in.direction, out);
    return out;
}

} // namespace

TEST_CASE("Pseudonyms keep a name's length and shape and a player id's range, and depend on the key", "[pseudonym]")
{
    Pseudonymizer a(KEY);
    Pseudonymizer b(KEY);
    Pseudonymizer other(deriveKey(seed(8), PSEUDONYM_KEY_LABEL));

    for (const std::string real : { "Abc", "Firemarshal", "Oshainspectorxx" })
    {
        const auto fake = a.name(real);
        CHECK(fake.size() == real.size());
        CHECK(fake != real);
        CHECK(std::isupper(static_cast<unsigned char>(fake[0])));
        CHECK(std::ranges::all_of(fake.substr(1), [](char c)
                                  {
                                      return std::islower(static_cast<unsigned char>(c)) != 0;
                                  }));
        CHECK(b.name(real) == fake);
        CHECK(other.name(real) != fake);
    }

    CHECK(a.playerId(0) == 0);
    CHECK(a.playerId(0x01001234) == 0x01001234); // an NPC
    CHECK(a.playerId(0x0AB61C) == b.playerId(0x0AB61C));
    CHECK(a.playerId(0x0AB61C) != other.playerId(0x0AB61C));
    std::set<uint32_t> seen;
    for (uint32_t id = 0x0A0000; id < 0x0B0000; ++id)
    {
        const auto fake = a.playerId(id);
        CHECK((fake != 0 && fake < 0x100000));
        seen.insert(fake);
    }
    CHECK(seen.size() == 0x10000); // no two ids share a pseudonym
    CHECK((a.playerId(0x5ABCDE) & 0xF00000) == 0x500000);

    CHECK(a.contentId(0) == 0);
    CHECK(a.contentId(23773279) >= 0x80000000u); // never a real content id
    CHECK(a.contentId(23773279) == b.contentId(23773279));
}

TEST_CASE("Keys derived for different uses differ", "[pseudonym]")
{
    CHECK(deriveKey(seed(), PSEUDONYM_KEY_LABEL) != deriveKey(seed(), ANONYMOUS_SIGNING_LABEL));
    CHECK(deriveKey(seed(), PSEUDONYM_KEY_LABEL) != deriveKey(seed(8), PSEUDONYM_KEY_LABEL));
}

TEST_CASE("Every mapped field of a real game packet gets its pseudonym, and no other byte changes", "[pseudonym]")
{
    size_t names = 0;
    size_t ids   = 0;
    for (const auto& in : corpus().packets)
    {
        if (in.channel != 0 || opcodeOf(in.data) == 0x028)
        {
            continue;
        }
        Pseudonymizer p(KEY);
        const auto    out = pseudonymized(p, in);
        const auto    it  = EXPECTED.find({ in.direction, opcodeOf(in.data) });

        std::vector<bool> allowed(in.data.size());
        if (it != EXPECTED.end())
        {
            for (const auto& field : it->second)
            {
                if (field.mode != 0 && (std::to_integer<uint8_t>(in.data[4]) & 0x3F) != field.mode)
                {
                    continue;
                }
                if (field.offset + std::min<size_t>(field.size, 4) > in.data.size())
                {
                    continue;
                }
                const auto end = std::min<size_t>(in.data.size(), field.offset + field.size);
                std::fill(allowed.begin() + field.offset, allowed.begin() + static_cast<ptrdiff_t>(end), true);
                if (field.size == 4)
                {
                    const auto real = u32(in.data, field.offset);
                    CHECK(u32(out, field.offset) == (isPlayer(real) ? p.playerId(real) : real));
                    ids += isPlayer(real) ? 1 : 0;
                }
                else if (field.size != 24)
                {
                    const auto real = text(in.data, field.offset, field.size);
                    if (isName(real))
                    {
                        CHECK(text(out, field.offset, field.size) == p.name(real));
                        for (size_t i = field.offset + real.size(); i < end; ++i)
                        {
                            CHECK(out[i] == std::byte{ 0 });
                        }
                        ++names;
                    }
                }
            }
        }
        for (size_t i = 0; i < in.data.size(); ++i)
        {
            if (!allowed[i])
            {
                INFO("opcode " << opcodeOf(in.data) << " byte " << i);
                CHECK(out[i] == in.data[i]);
            }
        }
    }
    CHECK(names > 20);
    CHECK(ids > 100);
}

TEST_CASE("A crafter's signature in an item's extra data gets a pseudonym of the same length", "[pseudonym]")
{
    const auto it = std::ranges::find_if(corpus().packets, [](const CorpusPacket& p)
                                         {
                                             return p.channel == 0 && opcodeOf(p.data) == 0x020;
                                         });
    REQUIRE(it != corpus().packets.end());
    Pseudonymizer p(KEY);
    const auto    out = pseudonymized(p, *it);
    // Bytes 12 to 23 of the extra data at 17: 6-bit codes, 11 to 36 for capitals and 37 to 62 for small letters.
    const auto decode = [](std::span<const std::byte> d)
    {
        std::string s;
        for (size_t pos = 0;; pos += 6)
        {
            const auto code = bitsOf(d.subspan(29, 12), pos, 6, true);
            if (code == 0)
            {
                return s;
            }
            s += static_cast<char>(code <= 36 ? 'A' + code - 11 : 'a' + code - 37);
        }
    };
    const auto real = decode(it->data);
    CHECK(real.size() == 4);
    CHECK(decode(out) == p.name(real));
    CHECK(std::equal(out.begin(), out.begin() + 29, it->data.begin()));
}

TEST_CASE("The action packet's actor and targets get pseudonyms, and its other bits stay", "[pseudonym]")
{
    size_t players = 0;
    for (const auto& in : corpus().packets)
    {
        if (in.channel != 0 || opcodeOf(in.data) != 0x028)
        {
            continue;
        }
        Pseudonymizer p(KEY);
        auto          out = pseudonymized(p, in);
        // Put the real ids back where the stream says they sit; the result must be the packet that went in.
        std::vector<size_t> at{ 40 };
        const auto          targets = bitsOf(in.data, 72, 6, false);
        size_t              pos     = 150;
        for (uint32_t t = 0; t < targets; ++t)
        {
            at.push_back(pos);
            const auto results = bitsOf(in.data, pos + 32, 4, false);
            pos += 36;
            for (uint32_t r = 0; r < results; ++r)
            {
                pos += 85;
                pos += bitsOf(in.data, pos, 1, false) ? 38 : 1;
                pos += bitsOf(in.data, pos, 1, false) ? 35 : 1;
            }
        }
        for (const auto bit : at)
        {
            const auto real = bitsOf(in.data, bit, 32, false);
            const auto fake = bitsOf(out, bit, 32, false);
            CHECK(fake == p.playerId(real));
            players += isPlayer(real) ? 1 : 0;
            for (size_t i = 0; i < 32; ++i)
            {
                const auto b     = bit + i;
                const auto value = (std::to_integer<uint8_t>(out[b / 8]) & ~(1u << (b % 8))) | (((real >> i) & 1) << (b % 8));
                out[b / 8]       = static_cast<std::byte>(value);
            }
        }
        CHECK(out == in.data);
    }
    CHECK(players > 5);
}

TEST_CASE("Search requests and replies for player ids get the same pseudonyms as game packets", "[pseudonym]")
{
    Pseudonymizer p(KEY);
    size_t        entries = 0;
    for (const auto& in : corpus().packets)
    {
        if (in.channel != 1)
        {
            continue;
        }
        const auto out  = pseudonymized(p, in);
        const auto type = std::to_integer<uint8_t>(in.data[0x0B]);
        CHECK(std::equal(out.begin(), out.begin() + 0x0C, in.data.begin()));
        if (type == 0x01)
        {
            CHECK(u32(out, 0x12) == p.playerId(u32(in.data, 0x12)));
            continue;
        }
        REQUIRE(type == 0x81);
        const size_t end = std::to_integer<size_t>(in.data[8]) | std::to_integer<size_t>(in.data[9]) << 8;
        // One entry per player: a size byte, then a name tag (0), its length and 7-bit characters, and later an id tag (8).
        for (size_t at = 0x18; at < end; at += 1 + std::to_integer<size_t>(in.data[at]))
        {
            size_t pos = (at + 1) * 8;
            REQUIRE(bitsOf(in.data, pos, 5, true) == 0);
            const auto  length = bitsOf(in.data, pos + 5, 4, true);
            std::string real;
            std::string fake;
            for (uint32_t i = 0; i < length; ++i)
            {
                real += static_cast<char>(bitsOf(in.data, pos + 9 + i * 7, 7, true));
                fake += static_cast<char>(bitsOf(out, pos + 9 + i * 7, 7, true));
            }
            CHECK(fake == p.name(real));
            ++entries;
        }
        for (size_t i = end; i < out.size(); ++i)
        {
            CHECK(out[i] == std::byte{ 0 });
        }
    }
    CHECK(entries > 0);
}

TEST_CASE("Search packets the pseudonymizer cannot read are zeroed past their type", "[pseudonym]")
{
    Pseudonymizer          p(KEY);
    std::vector<std::byte> request(40, std::byte{ 0x41 });
    request[0x0B] = std::byte{ 0x03 }; // a search, which may name a player
    p.packet(1, PacketDirection::ClientToServer, request);
    CHECK(std::all_of(request.begin() + 0x0C, request.end(), [](std::byte b)
                      {
                          return b == std::byte{ 0 };
                      }));
    std::vector<std::byte> auction(40, std::byte{ 0x41 });
    auction[0x0B] = std::byte{ 0x15 }; // an auction house item list, which names no one
    p.packet(1, PacketDirection::ClientToServer, auction);
    CHECK(auction[0x20] == std::byte{ 0x41 });
}

TEST_CASE("No real name or id from the corpus is anywhere in an anonymous capture", "[pseudonym]")
{
    const auto& c = corpus();
    REQUIRE(c.names.size() >= 3);
    REQUIRE(c.ids.size() >= 10);

    TempCapture   tmp;
    Pseudonymizer p(KEY);
    {
        auto cfg = config();
        // The recorder of the first public capture in the corpus.
        cfg.character.contentId   = 23773279;
        cfg.character.characterId = 701980;
        cfg.character.characterName.fill(0);
        std::ranges::copy(std::string_view("Firemarshal"), cfg.character.characterName.begin());
        cfg.character   = p.character(cfg.character);
        cfg.policy      = anonymousExclusionPolicy();
        cfg.signingSeed = deriveKey(seed(), ANONYMOUS_SIGNING_LABEL);
        Writer   w(tmp.path, cfg);
        uint64_t t = T0;
        for (const auto& in : c.packets)
        {
            auto data = in.data;
            p.packet(in.channel, in.direction, data);
            w.write({ .timestamp = t++, .direction = in.direction, .data = data, .channel = in.channel, .opcode = std::to_integer<uint16_t>(in.data.size() > 0x0B ? in.data[0x0B] : std::byte{}) });
        }
        w.close();
    }

    // The file as stored, and every packet decompressed.
    std::ifstream          file(tmp.path, std::ios::binary);
    std::vector<std::byte> raw;
    for (char ch; file.get(ch);)
    {
        raw.push_back(static_cast<std::byte>(ch));
    }
    std::vector<std::vector<std::byte>> packets;
    std::vector<uint8_t>                channels;
    Reader                              reader(tmp.path);
    for (ReadPacket packet; reader.next(packet);)
    {
        packets.emplace_back(packet.data.begin(), packet.data.end());
        channels.push_back(packet.channel);
    }
    REQUIRE(packets.size() == c.packets.size());
    // The corpus holds zone-ins of four recorders; the header's pseudonym is the one its recorder's zone-in now carries.
    CHECK(std::ranges::any_of(packets, [&](const std::vector<std::byte>& d)
                              {
                                  return d.size() >= 148 && opcodeOf(d) == 0x00A && u32(d, 4) == p.playerId(701980) && text(d, 132, 16) == p.name("Firemarshal");
                              }));
    CHECK(reader.policy().name == "xicap-anonymous");
    CHECK(reader.character().characterId == p.playerId(701980));
    CHECK(text(std::as_bytes(std::span(reader.character().characterName)), 0, 16) == p.name("Firemarshal"));

    const auto contains = [](std::span<const std::byte> hay, std::span<const std::byte> needle)
    {
        return std::ranges::search(hay, needle).begin() != hay.end();
    };
    // Bit by bit, as the action packet (32 bits, least significant first) and search replies (most significant first) pack them.
    const auto containsBits = [](std::span<const std::byte> hay, uint32_t value, size_t n, bool msbFirst)
    {
        for (size_t pos = 0; pos + n <= hay.size() * 8; ++pos)
        {
            if (bitsOf(hay, pos, n, msbFirst) == value)
            {
                return true;
            }
        }
        return false;
    };
    for (const auto& name : c.names)
    {
        INFO("name " << name);
        const auto bytes = std::as_bytes(std::span(name));
        CHECK(!contains(raw, bytes));
        for (size_t i = 0; i < packets.size(); ++i)
        {
            INFO("packet " << i);
            CHECK(!contains(packets[i], bytes));
            if (channels[i] == 1)
            {
                for (size_t pos = 0; pos + name.size() * 7 <= packets[i].size() * 8; ++pos)
                {
                    const bool here = std::ranges::all_of(std::views::iota(size_t{ 0 }, name.size()), [&](size_t k)
                                                          {
                                                              return bitsOf(packets[i], pos + k * 7, 7, true) == static_cast<uint8_t>(name[k]);
                                                          });
                    CHECK(!here);
                }
            }
        }
    }
    for (const auto id : c.ids)
    {
        INFO("id " << id);
        const std::array<std::byte, 4> bytes{ std::byte(id), std::byte(id >> 8), std::byte(id >> 16), std::byte(id >> 24) };
        CHECK(!contains(raw, bytes));
        for (size_t i = 0; i < packets.size(); ++i)
        {
            INFO("packet " << i);
            CHECK(!contains(packets[i], bytes));
            CHECK(!containsBits(packets[i], id, 32, false));
            if (channels[i] == 1)
            {
                CHECK(!containsBits(packets[i], id, 20, true));
            }
        }
    }
}
