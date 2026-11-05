#include "format/layout.h"
#include "frame/frame.h"
#include "policy/check.h"

#include <algorithm>
#include <format>

namespace xicap
{
namespace
{

auto ruleFor(const ExclusionPolicy& policy, uint8_t channel, PacketDirection direction, uint16_t opcode) noexcept -> const ExclusionRule*
{
    const auto rule = std::ranges::find_if(policy.rules, [&](const ExclusionRule& r)
                                           {
                                               return r.channel == channel && r.opcode == opcode &&
                                                      (r.direction == ExclusionDirection::Both || static_cast<uint8_t>(r.direction) == static_cast<uint8_t>(direction));
                                           });
    if (rule == policy.rules.end())
    {
        return nullptr;
    }

    return &*rule;
}

auto checkRule(const ExclusionRule& rule) -> void
{
    if (rule.action == ExclusionAction::Stub && (!frame::isGame(rule.channel) || !rule.ranges.empty()))
    {
        throw Error("xicap: a stub rule is for the game channel and has no byte ranges");
    }

    if (rule.action != ExclusionAction::Stub && rule.action != ExclusionAction::ZeroRange)
    {
        throw Error("xicap: unknown exclusion action");
    }

    if (rule.ranges.size() > UINT16_MAX)
    {
        throw Error("xicap: too many byte ranges in a rule");
    }

    // The header holds the opcode and size a reader checks.
    if (frame::isGame(rule.channel) && std::ranges::any_of(rule.ranges, [](const ByteRange& r)
                                                           {
                                                               return r.offset < format::GAME_HEADER_SIZE;
                                                           }))
    {
        throw Error(std::format("xicap: a range for game opcode {:#05x} starts inside the 4-byte header", rule.opcode));
    }
}

} // namespace

namespace policy
{

auto check(const ExclusionPolicy& policy) -> void
{
    if (policy.rules.size() > UINT16_MAX)
    {
        throw Error("xicap: too many exclusion rules");
    }

    uint64_t size{ sizeof(format::PolicyHeader) };
    for (const auto& rule : policy.rules)
    {
        checkRule(rule);
        size += sizeof(format::RuleHeader) + rule.ranges.size() * sizeof(ByteRange);
    }

    if (size > format::MAX_BLOCK_SIZE)
    {
        throw Error("xicap: exclusion policy over 16 MiB");
    }
}

} // namespace policy

auto defaultExclusionPolicy() -> const ExclusionPolicy&
{
    // The text players write to each other, after atom0s's XiPackets: chat (0x017 in, 0x0B5 out), tells (0x0B6), the
    // Assist Channel (0x0B7), and the linkshell message board (0x0CC in, 0x0E2 out). Offsets count the 4-byte header.
    const auto zero = [](ExclusionDirection direction, uint16_t opcode, uint32_t offset, uint32_t length)
    {
        return ExclusionRule{ .channel = 0, .direction = direction, .action = ExclusionAction::ZeroRange, .opcode = opcode, .ranges = { { offset, length } } };
    };
    static const auto policy = ExclusionPolicy{
        .name    = "xicap-default",
        .version = 2,
        .rules   = {
            zero(ExclusionDirection::ServerToClient, 0x017, 0x17, TO_END),
            zero(ExclusionDirection::ClientToServer, 0x0B5, 0x06, TO_END),
            zero(ExclusionDirection::ClientToServer, 0x0B6, 0x15, TO_END),
            zero(ExclusionDirection::ClientToServer, 0x0B7, 0x15, TO_END),
            zero(ExclusionDirection::ServerToClient, 0x0CC, 0x08, 128),
            zero(ExclusionDirection::ClientToServer, 0x0E2, 0x10, 128),
        },
    };
    return policy;
}

auto applyPolicy(const ExclusionPolicy& policy, const OutPacket& packet) -> StoredPacket
{
    auto stored = StoredPacket{
        .opcode = packet.opcode,
        .flags  = static_cast<uint16_t>((packet.provenance & PacketFlag::Provenance) | static_cast<uint16_t>(packet.direction)),
        .data   = { packet.data.begin(), packet.data.end() },
    };
    if (frame::isGame(packet.channel))
    {
        if (packet.data.size() < format::GAME_HEADER_SIZE)
        {
            throw Error("xicap: a game packet is at least 4 bytes");
        }

        stored.opcode = format::gameId(packet.data);
    }

    const auto* rule = ruleFor(policy, packet.channel, packet.direction, stored.opcode);
    if (rule == nullptr)
    {
        return stored;
    }

    if (rule->action == ExclusionAction::Stub)
    {
        stored.data.resize(format::GAME_HEADER_SIZE);
        stored.flags |= PacketFlag::Excluded;
        return stored;
    }

    for (const auto& range : rule->ranges)
    {
        if (range.offset < stored.data.size())
        {
            const auto length = std::min<uint64_t>(range.length, stored.data.size() - range.offset);
            std::fill_n(stored.data.begin() + range.offset, length, std::byte{ 0 });
        }
    }

    stored.flags |= PacketFlag::Redacted;
    return stored;
}

} // namespace xicap
