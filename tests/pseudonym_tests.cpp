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

// pseudonym_fields.tsv: the field map as data, for tools that check anonymous captures. Stream rows are left out.
struct Row
{
    uint8_t         channel{};
    PacketDirection direction{};
    uint16_t        opcode{};
    uint32_t        offset{};
    uint32_t        size{}; // 0xFFFFFFFF: to the packet's end
    uint32_t        count{};
    uint32_t        stride{};
    std::string     kind;
    uint8_t         when{};
    uint16_t        mask{};
    uint16_t        is{};
};

auto rows() -> const std::vector<Row>&
{
    static const std::vector<Row> out = []
    {
        std::vector<Row> rows;
        std::ifstream    in(XICAP_PSEUDONYM_FIELDS);
        REQUIRE(in);
        std::string line;
        while (std::getline(in, line))
        {
            if (!line.empty() && line.back() == '\r')
            {
                line.pop_back();
            }
            std::vector<std::string> f;
            std::istringstream       cells(line);
            for (std::string cell; std::getline(cells, cell, '\t');)
            {
                f.push_back(cell);
            }
            if (line.empty() || line[0] == '#' || f[0] == "channel" || f[7] == "stream")
            {
                continue;
            }
            REQUIRE(f.size() == 11);
            Row r{
                .channel   = static_cast<uint8_t>(std::stoul(f[0])),
                .direction = f[1] == "c2s" ? PacketDirection::ClientToServer : PacketDirection::ServerToClient,
                .opcode    = static_cast<uint16_t>(std::stoul(f[2], nullptr, 16)),
                .offset    = static_cast<uint32_t>(std::stoul(f[3])),
                .size      = f[4] == "end" ? 0xFFFFFFFF : static_cast<uint32_t>(std::stoul(f[4])),
                .count     = static_cast<uint32_t>(std::stoul(f[5])),
                .stride    = static_cast<uint32_t>(std::stoul(f[6])),
                .kind      = f[7],
            };
            if (f[8] != "-") // u16@<at>&<mask>==<value>
            {
                const auto amp = f[8].find('&');
                const auto eq  = f[8].find("==");
                r.when         = static_cast<uint8_t>(std::stoul(f[8].substr(4, amp - 4)));
                r.mask         = static_cast<uint16_t>(std::stoul(f[8].substr(amp + 1, eq - amp - 1), nullptr, 16));
                r.is           = static_cast<uint16_t>(std::stoul(f[8].substr(eq + 2), nullptr, 16));
            }
            rows.push_back(std::move(r));
        }
        return rows;
    }();
    return out;
}

auto opcodeOf(std::span<const std::byte> d) -> uint16_t
{
    return static_cast<uint16_t>((std::to_integer<uint16_t>(d[0]) | std::to_integer<uint16_t>(d[1]) << 8) & 0x1FF);
}

// The bytes the TSV's id, name and signature rows let pseudonymizing change in a packet.
auto documented(uint8_t channel, PacketDirection direction, std::span<const std::byte> d) -> std::vector<bool>
{
    std::vector<bool> out(d.size());
    const auto        opcode = channel == 0 ? opcodeOf(d) : std::to_integer<uint16_t>(d[0x0B]);
    for (const auto& r : rows())
    {
        if (r.kind == "text" || r.channel != channel || r.direction != direction || r.opcode != opcode)
        {
            continue;
        }
        if (r.mask != 0 && (r.when + 2u > d.size() || ((std::to_integer<uint16_t>(d[r.when]) | std::to_integer<uint16_t>(d[r.when + 1]) << 8) & r.mask) != r.is))
        {
            continue;
        }
        for (uint32_t i = 0; i < r.count; ++i)
        {
            const size_t at   = r.offset + i * r.stride;
            const size_t need = r.kind == "id" ? 4 : r.kind == "signature" ? 24
                                                                           : 1;
            if (at + need > d.size())
            {
                continue;
            }
            const size_t from = r.kind == "signature" ? at + 12 : at;
            std::fill(out.begin() + static_cast<ptrdiff_t>(from), out.begin() + static_cast<ptrdiff_t>(std::min<size_t>(d.size(), at + r.size)), true);
        }
    }
    return out;
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

TEST_CASE("pseudonym_fields.tsv lists the library's field map and the anonymous policy's text ranges", "[pseudonym]")
{
    const auto  map    = pseudonymFieldMap();
    const auto& policy = anonymousExclusionPolicy();
    size_t      i      = 0;
    size_t      t      = defaultExclusionPolicy().rules.size();
    for (const auto& r : rows())
    {
        if (r.kind == "text")
        {
            REQUIRE(t < policy.rules.size());
            const auto& rule = policy.rules[t++];
            CHECK(rule.channel == r.channel);
            CHECK(static_cast<uint8_t>(rule.direction) == static_cast<uint8_t>(r.direction));
            CHECK(rule.opcode == r.opcode);
            CHECK(rule.action == ExclusionAction::ZeroRange);
            REQUIRE(rule.ranges.size() == 1);
            CHECK(rule.ranges[0].offset == r.offset);
            CHECK(rule.ranges[0].length == r.size);
            continue;
        }
        REQUIRE(i < map.size());
        const auto& m = map[i++];
        INFO("row " << i << " opcode " << r.opcode << " offset " << r.offset);
        CHECK(m.channel == r.channel);
        CHECK(m.direction == r.direction);
        CHECK(m.opcode == r.opcode);
        CHECK(m.offset == r.offset);
        CHECK(m.size == r.size);
        CHECK(m.count == r.count);
        CHECK(m.stride == r.stride);
        CHECK(r.kind == (m.kind == PseudonymKind::Id ? "id" : m.kind == PseudonymKind::Name ? "name"
                                                                                            : "signature"));
        CHECK(m.when == r.when);
        CHECK(m.mask == r.mask);
        CHECK(m.is == r.is);
    }
    CHECK(i == map.size());
    CHECK(t == policy.rules.size());
    // Nothing is stubbed that the default does not stub: every packet keeps its layout.
    CHECK(std::ranges::count(policy.rules, ExclusionAction::Stub, &ExclusionRule::action) == std::ranges::count(defaultExclusionPolicy().rules, ExclusionAction::Stub, &ExclusionRule::action));
}

namespace
{

// Pseudonymizes a packet with a fresh pseudonymizer and checks that only documented bytes changed, and that each
// documented id and name holds its pseudonym. Returns how many real ids and names it found.
auto checkLayout(uint8_t channel, PacketDirection direction, const std::vector<std::byte>& in) -> std::pair<size_t, size_t>
{
    Pseudonymizer p(KEY);
    auto          out = in;
    p.packet(channel, direction, out);
    const auto allowed = documented(channel, direction, in);
    const auto opcode  = channel == 0 ? opcodeOf(in) : std::to_integer<uint16_t>(in[0x0B]);
    for (size_t i = 0; i < in.size(); ++i)
    {
        if (!allowed[i])
        {
            INFO("channel " << int(channel) << " opcode " << opcode << " byte " << i);
            CHECK(out[i] == in[i]);
        }
    }
    size_t ids   = 0;
    size_t names = 0;
    for (const auto& r : rows())
    {
        if (r.channel != channel || r.direction != direction || r.opcode != opcode || (r.kind != "id" && r.kind != "name"))
        {
            continue;
        }
        if (r.mask != 0 && ((std::to_integer<uint16_t>(in[r.when]) | std::to_integer<uint16_t>(in[r.when + 1]) << 8) & r.mask) != r.is)
        {
            continue;
        }
        for (uint32_t k = 0; k < r.count; ++k)
        {
            const size_t at = r.offset + k * r.stride;
            if (r.kind == "id" && at + 4 <= in.size())
            {
                const auto real = u32(in, at);
                CHECK(u32(out, at) == (isPlayer(real) ? p.playerId(real) : real));
                ids += isPlayer(real) ? 1 : 0;
            }
            else if (r.kind == "name" && at < in.size())
            {
                const auto real = text(in, at, r.size);
                if (isName(real))
                {
                    CHECK(text(out, at, r.size) == p.name(real));
                    for (size_t j = at + real.size(); j < std::min<size_t>(in.size(), at + r.size); ++j)
                    {
                        CHECK(out[j] == std::byte{ 0 });
                    }
                    ++names;
                }
            }
        }
    }
    return { ids, names };
}

auto put(std::vector<std::byte>& d, size_t at, std::string_view s) -> void
{
    std::ranges::copy(std::as_bytes(std::span(s)), d.begin() + static_cast<ptrdiff_t>(at));
}

auto put32(std::vector<std::byte>& d, size_t at, uint32_t v) -> void
{
    for (size_t k = 0; k < 4; ++k)
    {
        d[at + k] = std::byte(v >> (8 * k));
    }
}

} // namespace

TEST_CASE("Every real game packet keeps its layout: only the fields the field map names change", "[pseudonym]")
{
    size_t names = 0;
    size_t ids   = 0;
    for (const auto& in : corpus().packets)
    {
        if (in.channel != 0 || opcodeOf(in.data) == 0x028)
        {
            continue;
        }
        const auto [i, n] = checkLayout(in.channel, in.direction, in.data);
        ids += i;
        names += n;
    }
    CHECK(names > 20);
    CHECK(ids > 100);
}

TEST_CASE("Packets once stubbed keep their layout: chat, proposals, votes, ballista, and the concierge", "[pseudonym]")
{
    const auto s2c = PacketDirection::ServerToClient;
    const auto c2s = PacketDirection::ClientToServer;
    struct Case
    {
        PacketDirection        direction;
        std::vector<std::byte> data;
        size_t                 ids;
        size_t                 names;
    };
    std::vector<Case> cases;
    const auto        add = [&](PacketDirection d, uint16_t opcode, size_t size, auto fill, size_t ids, size_t names)
    {
        auto p = gamePacket(opcode, size, 0);
        fill(p);
        cases.push_back({ d, std::move(p), ids, names });
    };
    // Layouts after LandSandBoat's packet definitions.
    add(s2c, 0x014, 48, [](auto& p)
        {
            put32(p, 4, 0x0AB61C);
            put32(p, 8, 0x1234);
            put(p, 12, "see you");
        },
        1,
        0);
    add(s2c, 0x017, 48, [](auto& p)
        {
            p[4] = std::byte{ 1 };
            put(p, 8, "Audithor");
            put(p, 23, "hello");
        },
        0,
        1);
    add(s2c, 0x078, 64, [](auto& p)
        {
            put32(p, 4, 0x0A0B0C);
            put32(p, 8, 6);
            put(p, 14, "Audithor");
            p[29] = std::byte{ 1 };
            put(p, 30, "Sky?");
        },
        1,
        1);
    add(s2c, 0x079, 64, [](auto& p)
        {
            put32(p, 4, 6);
            p[26] = std::byte{ 1 };
            put(p, 29, "Audithor");
            put(p, 44, "Sky?");
        },
        0,
        1);
    add(s2c, 0x0CC, 176, [](auto& p)
        {
            put(p, 8, "Welcome");
            put32(p, 136, 0x6A000000);
            put(p, 140, "Audithor");
        },
        0,
        1);
    add(s2c, 0x0E6, 40, [](auto& p)
        {
            put32(p, 4, 3 << 6);
            put32(p, 8, 0x0AB61C);
        },
        1,
        0); // ballista scout
    add(s2c, 0x0E6, 40, [](auto& p)
        {
            put32(p, 4, 2 << 6);
            put32(p, 8, 0x0AB61C);
        },
        0,
        0); // ballista scores: Petra, not an id
    add(s2c, 0x048, 128, [](auto& p)
        {
            put32(p, 4, 0xFEFEFEFE);
            put(p, 28, "22d");
        },
        0,
        0); // concierge: no player in it
    add(c2s, 0x0A0, 32, [](auto& p)
        {
            p[4] = std::byte{ 1 };
            put(p, 5, "Sky?");
        },
        0,
        0);
    add(c2s, 0x0A1, 24, [](auto& p)
        {
            p[4] = std::byte{ 1 };
            put(p, 5, "Audithor");
        },
        0,
        1);
    add(c2s, 0x0B6, 40, [](auto& p)
        {
            put(p, 6, "Audithor");
            put(p, 21, "hi");
        },
        0,
        1);
    add(c2s, 0x0B7, 40, [](auto& p)
        {
            put(p, 6, "Audithor");
            put(p, 21, "hi");
        },
        0,
        1);
    add(c2s, 0x0E2, 48, [](auto& p)
        {
            put32(p, 12, 0x0AB61C);
            put(p, 16, "Welcome");
        },
        1,
        0);
    for (const auto& c : cases)
    {
        INFO("opcode " << opcodeOf(c.data));
        const auto [ids, names] = checkLayout(0, c.direction, c.data);
        CHECK(ids == c.ids);
        CHECK(names == c.names);
    }

    // The writer then zeroes only the text the anonymous policy names.
    TempCapture tmp;
    {
        auto cfg   = config();
        cfg.policy = anonymousExclusionPolicy();
        Writer   w(tmp.path, cfg);
        uint64_t t = T0;
        for (const auto& c : cases)
        {
            w.write(t++, c.direction, c.data);
        }
        w.close();
    }
    Reader r(tmp.path);
    size_t at = 0;
    for (ReadPacket packet; r.next(packet); ++at)
    {
        const auto& in   = cases[at].data;
        const auto* rule = ruleFor(anonymousExclusionPolicy(), 0, packet.direction, packet.opcode);
        if (rule != nullptr && rule->action == ExclusionAction::Stub)
        {
            continue; // the default's, until its version 2
        }
        REQUIRE(packet.data.size() == in.size());
        for (size_t i = 0; i < in.size(); ++i)
        {
            bool zeroed = false;
            if (rule != nullptr)
            {
                for (const auto& range : rule->ranges)
                {
                    zeroed = zeroed || (i >= range.offset && (range.length == 0xFFFFFFFF || i < range.offset + range.length));
                }
            }
            INFO("opcode " << packet.opcode << " byte " << i);
            CHECK(packet.data[i] == (zeroed ? std::byte{ 0 } : in[i]));
        }
    }
    CHECK(at == cases.size());
}

TEST_CASE("A call for a GM keeps its blocks: lobby ids and names get pseudonyms, typed text is zeroed", "[pseudonym]")
{
    auto p                         = gamePacket(0x0D3, 160, 0);
    p[4]                           = std::byte{ 2 }; // a GM call
    p[7]                           = std::byte{ 3 }; // blocks
    const std::string_view typed   = "GMCALL.INPUT:Audithor is stuck";
    const std::string_view setting = "GENERIC.CLILANG:2";
    size_t                 at      = 8;
    p[at]                          = std::byte{ 3 };
    p[at + 1]                      = std::byte(4 + typed.size());
    put(p, at + 4, typed);
    const size_t typedAt = at + 4;
    at += 4 + typed.size();
    p[at]     = std::byte{ 3 };
    p[at + 1] = std::byte(4 + setting.size());
    put(p, at + 4, setting);
    at += 4 + setting.size();
    p[at]     = std::byte{ 4 };
    p[at + 1] = std::byte{ 4 + 28 };
    put32(p, at + 4 + 8, 0x0AB61C);
    put(p, at + 4 + 12, "Audithor");
    const size_t lobby = at + 4;

    Pseudonymizer ps(KEY);
    auto          out = p;
    ps.packet(0, PacketDirection::ClientToServer, out);
    const auto colon = typedAt + typed.find(':') + 1;
    for (size_t i = 0; i < p.size(); ++i)
    {
        INFO("byte " << i);
        if (i >= colon && i < typedAt + typed.size())
        {
            CHECK(out[i] == std::byte{ 0 });
        }
        else if (i < lobby + 8 || i >= lobby + 28)
        {
            CHECK(out[i] == p[i]);
        }
    }
    CHECK(u32(out, lobby + 8) == ps.playerId(0x0AB61C));
    CHECK(text(out, lobby + 12, 16) == ps.name("Audithor"));
}

TEST_CASE("Search packets keep their layout: name filters, party and comment ids, auction names, and hashes", "[pseudonym]")
{
    const auto c2s          = PacketDirection::ClientToServer;
    const auto s2c          = PacketDirection::ServerToClient;
    const auto searchPacket = [](uint8_t type, size_t size)
    {
        std::vector<std::byte> d(size);
        put32(d, 0, static_cast<uint32_t>(size));
        put(d, 4, "IXFF");
        d[0x0B] = std::byte{ type };
        return d;
    };
    const auto zeroFrom = [](const std::vector<std::byte>& d, size_t from)
    {
        return std::all_of(d.begin() + static_cast<ptrdiff_t>(from), d.end(), [](std::byte b)
                           {
                               return b == std::byte{ 0 };
                           });
    };

    // A search for a name and a zone: tags of 5 bits, a sort and a presence bit, then a 5-bit length and 7-bit
    // characters, most significant bit first.
    {
        auto              d = searchPacket(0x03, 0x30);
        std::vector<bool> bits;
        const auto        push = [&](uint32_t v, size_t n)
        {
            for (size_t i = 0; i < n; ++i)
            {
                bits.push_back(((v >> (n - 1 - i)) & 1) != 0);
            }
        };
        push(0x00, 5);
        push(0, 1);
        push(1, 1);
        push(6, 5);
        for (const char c : std::string_view("Nouurs"))
        {
            push(static_cast<uint8_t>(c), 7);
        }
        push(0x01, 5);
        push(0, 1);
        push(1, 1);
        push(236, 10);
        d[0x10] = std::byte((bits.size() + 7) / 8);
        for (size_t i = 0; i < bits.size(); ++i)
        {
            d[0x11 + i / 8] |= std::byte(static_cast<uint8_t>(bits[i]) << (7 - i % 8));
        }
        Pseudonymizer p(KEY);
        auto          out = d;
        p.packet(1, c2s, out);
        const size_t name = 0x11 * 8 + 12;
        std::string  fake;
        for (size_t i = 0; i < 6; ++i)
        {
            fake += static_cast<char>(bitsOf(out, name + i * 7, 7, true));
        }
        CHECK(fake == p.name("Nouurs"));
        for (size_t pos = 0; pos < d.size() * 8; ++pos)
        {
            if (pos < name || pos >= name + 42)
            {
                INFO("bit " << pos);
                CHECK(bitsOf(out, pos, 1, true) == bitsOf(d, pos, 1, true));
            }
        }
    }

    // A party list request names the party and alliance by their leaders' ids; linkshell ids stay.
    {
        auto d = searchPacket(0x02, 0x20);
        put32(d, 0x10, 0x0AB61C);
        put32(d, 0x14, 0x0A0B0C);
        put32(d, 0x18, 0x00123456);
        CHECK(checkLayout(1, c2s, d).first == 2);
    }

    // Auction history: seller and buyer names, then the client's hash, zeroed.
    {
        auto d = searchPacket(0x85, 0x20 + 80 + 20);
        d[8]   = std::byte{ 0x20 + 80 };
        put32(d, 0x20, 1000);
        put(d, 0x28, "Audithor");
        put(d, 0x38, "Nouurs");
        put32(d, 0x20 + 40, 2000);
        put(d, 0x28 + 40, "Mule");
        std::fill(d.begin() + 0x20 + 80, d.end(), std::byte{ 0x5A });
        Pseudonymizer p(KEY);
        auto          out = d;
        p.packet(1, s2c, out);
        CHECK(text(out, 0x28, 16) == p.name("Audithor"));
        CHECK(text(out, 0x38, 16) == p.name("Nouurs"));
        CHECK(text(out, 0x28 + 40, 16) == p.name("Mule"));
        CHECK(u32(out, 0x20) == 1000);
        CHECK(u32(out, 0x20 + 40) == 2000);
        CHECK(zeroFrom(out, 0x20 + 80));
        auto hashless = d;
        std::fill(hashless.begin() + 0x20 + 80, hashless.end(), std::byte{ 0 });
        checkLayout(1, s2c, hashless);
    }

    // A comment: the player's id; its text goes to the policy, and the hash after the length is zeroed.
    {
        auto d = searchPacket(0x88, 204);
        d[8]   = std::byte{ 154 };
        put32(d, 0x18, 0x0AB61C);
        put(d, 0x1E, "LFG Nouurs");
        d[0xA0] = std::byte{ 0x5A };
        Pseudonymizer p(KEY);
        auto          out = d;
        p.packet(1, s2c, out);
        CHECK(u32(out, 0x18) == p.playerId(0x0AB61C));
        CHECK(zeroFrom(out, 154));
        CHECK(std::equal(out.begin(), out.begin() + 0x18, d.begin()));
    }

    // A type this library does not read: zeroed past its type.
    {
        auto d = searchPacket(0x07, 40);
        put(d, 0x10, "Nouurs");
        Pseudonymizer p(KEY);
        auto          out = d;
        p.packet(1, c2s, out);
        CHECK(std::equal(out.begin(), out.begin() + 0x0C, d.begin()));
        CHECK(zeroFrom(out, 0x0C));
    }
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
        if ((packet.flags & PacketFlag::Excluded) != 0) // only what the default stubs, never more
        {
            const auto* rule = ruleFor(defaultExclusionPolicy(), packet.channel, packet.direction, packet.opcode);
            CHECK((rule != nullptr && rule->action == ExclusionAction::Stub));
        }
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
