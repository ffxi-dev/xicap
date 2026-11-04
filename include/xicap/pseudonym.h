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

// The default policy, plus what anonymous captures cannot keep: game packets with player text or names the pseudonymizer
// cannot place are stubbed, and search packets it cannot read are zeroed past their type. Its version is the field map's.
[[nodiscard]] auto anonymousExclusionPolicy() -> const ExclusionPolicy&;

// Replaces player names and ids in packets, in place, with pseudonyms keyed by the key: the same name or id always gets
// the same pseudonym, and without the key no one can tell which real name gave it. A name keeps its length and stays
// letters, capitalized; a player id stays a player id. NPC and mob ids (0x01000000 and up) pass unchanged.
//
// Two passes. The field map (see pseudonym.cpp) rewrites the fields known to hold a player's name or id. Then every real
// name and id rewritten so far is replaced wherever else it appears in the packet: retail leaves stale bytes in fields it
// does not fill. A name or id never seen in a mapped field before can stay in such stale bytes.
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
