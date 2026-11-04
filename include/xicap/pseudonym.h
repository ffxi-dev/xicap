#pragma once

#include "types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace xicap
{

using PseudonymKey = std::array<uint8_t, 32>;

// What a recorder derives from its install's seed: the pseudonym key, when no account key is at hand, and the seed that
// signs its anonymous captures, so that no key links them to its other captures.
inline constexpr std::string_view PSEUDONYM_KEY_LABEL     = "xicap pseudonym key";
inline constexpr std::string_view ANONYMOUS_SIGNING_LABEL = "xicap anonymous signing";

// A 32-byte key for one use, named by label: BLAKE2b keyed with the seed.
[[nodiscard]] auto deriveKey(const SecretSeed& seed, std::string_view label) -> std::array<uint8_t, 32>;

// The default policy, plus zeroed ranges over the text players write that the default keeps. Nothing is stubbed: every
// packet keeps its layout. Its version is the field map's.
[[nodiscard]] auto anonymousExclusionPolicy() -> const ExclusionPolicy&;

// One row of the field map: `count` fields `stride` bytes apart, from `offset` in packets of this channel, direction
// and opcode (the search channel's opcode is its byte 0x0B). With `mask` set, only when the u16 at `when`, masked,
// equals `is`. A field past the packet's end is skipped. pseudonym_fields.tsv lists the same rows for other tools.
enum class PseudonymKind : uint8_t
{
    Id,        // u32, little-endian: a player id gets its pseudonym, anything else stays
    Name,      // `size` bytes of NUL-padded text: letters only get their pseudonym and the rest of the field zeroed
    Signature, // an item's 24-byte extra data: a crafter's name in 6-bit codes at bytes 12 to 23
};

struct PseudonymPlace
{
    uint8_t         channel;
    PacketDirection direction;
    uint16_t        opcode;
    uint16_t        offset;
    PseudonymKind   kind;
    uint8_t         size; // bytes: 4 for an id, 24 for extra data
    uint8_t         count;
    uint8_t         stride;
    uint8_t         when;
    uint16_t        mask;
    uint16_t        is;
};

[[nodiscard]] auto pseudonymFieldMap() -> std::span<const PseudonymPlace>;

// Replaces player names and ids in packets, in place, with pseudonyms keyed by the key: the same name or id always gets
// the same pseudonym, and without the key no one can tell which real name gave it. A name keeps its length and stays
// letters, capitalized; a player id stays a player id. NPC and mob ids (0x01000000 and up) pass unchanged. Every byte
// it does not name stays as it was, so each packet keeps its layout.
//
// Three passes. The field map rewrites the fixed fields; walkers rewrite the fields of bit streams and block lists
// (FORMAT.md, Anonymous captures). Then every real name and id met so far is replaced wherever else it appears in the
// packet: retail leaves stale bytes in fields it does not fill. A name or id never seen in a mapped field before can
// stay in such stale bytes.
class Pseudonymizer
{
public:
    explicit Pseudonymizer(const PseudonymKey& key);

    [[nodiscard]] auto name(std::string_view real) -> std::string;
    [[nodiscard]] auto playerId(uint32_t id) -> uint32_t;
    [[nodiscard]] auto contentId(uint32_t id) const -> uint32_t; // set the high bit, which real content ids never use
    [[nodiscard]] auto character(const CharacterIdentity& real) -> CharacterIdentity;

    // A packet as the writer takes it: from its 4-byte header on the game channel, from its size on the search channel.
    auto packet(uint8_t channel, PacketDirection direction, std::span<std::byte> data) -> void;

private:
    PseudonymKey                                 key_;
    std::unordered_map<std::string, std::string> names_; // real to pseudonym, for the sweep
    std::unordered_map<uint32_t, uint32_t>       ids_;
};

} // namespace xicap
