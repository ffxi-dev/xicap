#include "internal/transcode.h"
#include "internal/access.h"
#include "internal/chain.h"
#include "internal/crc32.h"

#include "monocypher.h"
#include "xicap/reader.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <format>
#include <map>
#include <optional>
#include <random>
#include <stdexcept>
#include <tuple>

namespace xicap
{
namespace internal
{
namespace
{

[[noreturn]] auto refuse(const std::string& why) -> void
{
    throw Error(ErrorCode::TranscodeRefused, "xicap: transcode refused: " + why);
}

[[noreturn]] auto mismatch(const std::string& why) -> void
{
    throw Error(ErrorCode::TranscodeMismatch, "xicap: transcode check failed: " + why);
}

template <typename T>
auto hexOf(const T& bytes) -> std::string
{
    std::string out;
    for (const auto b : bytes)
    {
        out += std::format("{:02x}", static_cast<unsigned>(b));
    }
    return out;
}

auto blockType(const std::vector<uint8_t>& block) -> uint32_t
{
    uint32_t type = 0;
    std::memcpy(&type, block.data(), sizeof(type));
    return type;
}

// Resign: the header names the new key and format 4; the blocks lose the dictionary and gain a SOURCE block naming
// src, unless src has one.
auto resignStart(Reader& src, const Verification& v, const TranscodeOptions& options, std::vector<uint8_t>& header, std::vector<std::vector<uint8_t>>& blocks) -> void
{
    std::erase_if(blocks, [](const std::vector<uint8_t>& block)
                  {
                      return blockType(block) == EXT_ZSTD_DICT;
                  });
    if (!std::ranges::any_of(blocks, [](const std::vector<uint8_t>& block)
                             {
                                 return blockType(block) == EXT_SOURCE;
                             }))
    {
        const auto& trailer = Access::trailer(src);
        std::string lines   = std::format("signing-key {}\nsigned-to-end {}\nverified-packets {}\nfooter-signature {}\ntranscoded-by {}\n",
                                          hexOf(src.signingKey()),
                                          v.signedToEnd ? "yes" : "no",
                                          v.verifiedPackets,
                                          src.complete() ? hexOf(trailer.signature) : "none",
                                          options.agent);
        SourceInfo  source{ .format = "xicap", .formatVersion = std::format("{}.{}", src.versionMajor(), src.versionMinor()), .skippedRecords = 0, .utcOffsetSeconds = 0, .sourceHash = options.sourceHash, .metadata = { lines.begin(), lines.end() } };
        source.metadata.insert(source.metadata.end(), options.metadata.begin(), options.metadata.end());
        blocks.push_back(encodeBlock(EXT_SOURCE, encodeSource(source)));
    }

    const SigningKey key(options.seed);
    const auto       count                 = static_cast<uint32_t>(blocks.size());
    header[offsetof(Header, versionMajor)] = VERSION_MAJOR;
    header[offsetof(Header, versionMinor)] = VERSION_MINOR;
    std::memcpy(header.data() + offsetof(Header, extensionCount), &count, sizeof(count));
    std::memset(header.data() + offsetof(Header, dictionaryId), 0, sizeof(uint32_t));
    std::memcpy(header.data() + offsetof(Header, signingKey), key.publicKey().data(), key.publicKey().size());
    const auto crc = crc32({ header.data(), header.size() - sizeof(uint32_t) });
    std::memcpy(header.data() + header.size() - sizeof(crc), &crc, sizeof(crc));
}

// A file beside dst that no other call names, and that becomes dst only once whole: a failed call leaves dst as it
// was, and no call can write over its own src.
class Staged
{
public:
    explicit Staged(const std::filesystem::path& dst)
    : dst_(dst)
    {
        std::random_device rd;
        path_ = std::filesystem::path(dst).concat(std::format(".{:08x}{:08x}.tmp", rd(), rd()));
    }
    ~Staged()
    {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }
    Staged(const Staged&)                    = delete;
    auto operator=(const Staged&) -> Staged& = delete;

    [[nodiscard]] auto path() const -> const std::filesystem::path&
    {
        return path_;
    }
    auto publish() -> void
    {
        std::filesystem::rename(path_, dst_);
    }

private:
    std::filesystem::path dst_;
    std::filesystem::path path_;
};

// Reads src and dst side by side; any difference is a mismatch.
auto compare(const std::filesystem::path& src, const std::filesystem::path& dst) -> void
{
    Reader     a(src), b(dst);
    ReadPacket pa{}, pb{};
    for (uint64_t i = 0;; ++i)
    {
        const bool na = a.next(pa);
        const bool nb = b.next(pb);
        if (na != nb)
        {
            mismatch(std::format("packet {} is in only one of the files", i));
        }
        if (!na)
        {
            return;
        }
        const bool same = pa.timestamp == pb.timestamp && pa.channel == pb.channel && pa.flags == pb.flags && pa.opcode == pb.opcode &&
                          std::ranges::equal(pa.data, pb.data) && pa.markers.size() == pb.markers.size() &&
                          std::ranges::equal(pa.markers, pb.markers, [](const ReadMarker& x, const ReadMarker& y)
                                             {
                                                 return x.kind == y.kind && x.text == y.text;
                                             });
        if (!same)
        {
            mismatch(std::format("packet {} differs", i));
        }
    }
}

// What a reader needs to set the scene at a cut's start: the last zone-in before it, then, since that zone-in, the
// last packet of each key below. A newer packet with the same key replaces the older; a packet is kept while any
// key still names it.
class Scene
{
public:
    auto add(uint64_t index, const ReadPacket& p) -> void
    {
        if (p.channel != static_cast<uint8_t>(Channel::Game))
        {
            return;
        }
        const auto* d     = reinterpret_cast<const uint8_t*>(p.data.data());
        const auto  n     = p.data.size();
        const auto  field = [&](size_t at, size_t size) -> uint64_t
        {
            uint64_t v = 0;
            if (at + size <= n)
            {
                std::memcpy(&v, d + at, size);
            }
            return v;
        };
        if (p.direction == PacketDirection::ClientToServer)
        {
            if (p.opcode == 0x015) // the recorder's position
            {
                keep({ 1, p.opcode, 0 }, index, p);
            }
            return;
        }
        switch (p.opcode)
        {
            case 0x00A: // zone-in: what came before it was another zone
                latest_.clear();
                kept_.clear();
                keep({ 0, p.opcode, 0 }, index, p);
                break;
            case 0x00D: // a player's update, by id, the last carrying each part (position, claim, general, name, model)
            case 0x00E: // an NPC's or mob's
            {
                const auto id    = field(4, 4) << 8;
                const auto parts = field(10, 1);
                for (uint64_t part = 0; part < 5; ++part)
                {
                    if (parts & 0x20) // despawned
                    {
                        release({ 0, p.opcode, id | part });
                    }
                    else if (parts >> part & 1)
                    {
                        keep({ 0, p.opcode, id | part }, index, p);
                    }
                }
                break;
            }
            case 0x037: // the recorder's status
            case 0x051: // its gear's look
            case 0x057: // weather
            case 0x061: // its job, level, HP and MP
            case 0x076: // the party's status icons
            case 0x0C8: // the party and alliance list
                keep({ 0, p.opcode, 0 }, index, p);
                break;
            case 0x05F: // music, by slot
            case 0x063: // the recorder's status icons and more, by type
                keep({ 0, p.opcode, field(4, 2) }, index, p);
                break;
            case 0x0DD: // a party member, by id
            case 0x0DF:
            case 0x0E2:
                keep({ 0, p.opcode, field(4, 4) }, index, p);
                break;
            default:
                break;
        }
    }

    // The packets kept, in the order they were read.
    [[nodiscard]] auto packets() const -> const std::map<uint64_t, std::pair<CopiedPacket, int>>&
    {
        return kept_;
    }

private:
    using Key = std::tuple<uint8_t, uint16_t, uint64_t>; // direction, opcode, what the packet is about

    auto keep(const Key& key, uint64_t index, const ReadPacket& p) -> void
    {
        release(key);
        latest_[key]     = index;
        auto [it, added] = kept_.try_emplace(index);
        if (added)
        {
            const auto* d    = reinterpret_cast<const uint8_t*>(p.data.data());
            it->second.first = { .timestamp = p.timestamp, .flags = p.flags, .channel = p.channel, .opcode = p.opcode, .data = { d, d + p.data.size() }, .markers = {} };
        }
        it->second.second++;
    }

    auto release(const Key& key) -> void
    {
        const auto it = latest_.find(key);
        if (it == latest_.end())
        {
            return;
        }
        if (const auto k = kept_.find(it->second); --k->second.second == 0)
        {
            kept_.erase(k);
        }
        latest_.erase(it);
    }

    std::map<Key, uint64_t>                          latest_;
    std::map<uint64_t, std::pair<CopiedPacket, int>> kept_; // by index: the packet and how many keys name it
};

} // namespace

auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, const TranscodeOptions& options, const TranscodeHooks& hooks) -> TranscodeResult
{
    Reader     in(src);
    const auto v    = in.verify();
    const bool seal = options.signing == Signing::Seal;
    if (seal && in.versionMajor() == 3)
    {
        refuse("a seal keeps the signer's signatures, which format 3 signs over compressed bytes; resign it");
    }
    if (seal && in.complete() && !v.signedToEnd)
    {
        refuse("a complete file not signed to the end");
    }

    auto header = Access::headerBytes(in);
    auto blocks = Access::blockBytes(in);
    if (!seal)
    {
        resignStart(in, v, options, header, blocks);
    }
    // A cut-off file keeps the last checkpoint that verifies.
    std::optional<CheckpointPayload> carried;
    if (seal && !in.complete() && v.verifiedPackets > 0)
    {
        carried = CheckpointPayload{ .packets = v.verifiedPackets, .digest = v.checkpointDigest, .signature = v.checkpointSignature };
    }

    Staged          tmp(dst);
    TranscodeResult result{ .packets = 0, .markers = 0, .bytesIn = std::filesystem::file_size(src), .bytesOut = 0 };
    {
        const auto writer = Access::rewriter(tmp.path(), options.policy, std::move(header), std::move(blocks), seal ? nullptr : &options.seed);
        if (seal)
        {
            if (in.complete())
            {
                Access::copyFooter(*writer, Access::trailer(in).signature);
            }
            else
            {
                Access::endUnsigned(*writer);
            }
            const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            Access::seal(*writer, options.seed, options.agent, hooks.sealedAt != 0 ? hooks.sealedAt : static_cast<uint64_t>(now));
        }
        ReadPacket   p{};
        CopiedPacket copy;
        while (in.next(p))
        {
            if (hooks.edit)
            {
                const auto* d = reinterpret_cast<const uint8_t*>(p.data.data());
                copy          = { p.timestamp, p.flags, p.channel, p.opcode, { d, d + p.data.size() }, { p.markers.begin(), p.markers.end() } };
                hooks.edit(result.packets, copy);
                p = { .timestamp = copy.timestamp, .channel = copy.channel, .opcode = copy.opcode, .flags = copy.flags, .direction = p.direction, .data = std::as_bytes(std::span{ copy.data }), .markers = copy.markers };
            }
            result.markers += p.markers.size();
            Access::add(*writer, p);
            result.packets++;
            if (carried && result.packets == carried->packets)
            {
                Access::carry(*writer, *carried);
            }
        }
        writer->close();
    }
    if (hooks.check)
    {
        compare(src, tmp.path());
        Reader     out(tmp.path());
        const auto w    = out.verify();
        const bool good = out.complete() && !w.firstFailureOffset &&
                          (seal ? (in.complete() ? w.signedToEnd : w.verifiedPackets == (carried ? carried->packets : 0)) && w.seal && w.seal->good
                                : w.signedToEnd);
        if (!good)
        {
            mismatch("its signatures do not verify as expected");
        }
    }
    result.bytesOut = std::filesystem::file_size(tmp.path());
    tmp.publish();
    return result;
}

} // namespace internal

auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, const TranscodeOptions& options) -> TranscodeResult
{
    return internal::transcode(src, dst, options, {});
}

auto cut(const std::filesystem::path& src, const std::filesystem::path& dst, const CutOptions& options) -> void
{
    if (options.first > options.last)
    {
        throw std::invalid_argument("xicap: a cut's first packet is after its last");
    }
    Reader       reader{ src };
    WriterConfig config{};
    config.captureAgent  = options.agent;
    config.clientVersion = reader.clientVersion();
    config.character     = reader.character();
    config.clockSource   = reader.clockSource();
    config.origin        = Origin::Converted;
    config.network       = reader.network();
    config.startContext  = options.first == 0 ? reader.startContext() : StartContext::MidSession;
    config.signingSeed   = options.seed;
    config.policy        = reader.policy();
    // The same range of the same recording always cuts to the same file: its id comes from the recording's hash and
    // the range, not from a random draw.
    uint8_t idInput[64 + 16]{};
    std::ranges::copy(options.sourceHash, idInput);
    std::memcpy(idInput + 64, &options.first, 8);
    std::memcpy(idInput + 72, &options.last, 8);
    crypto_blake2b(config.captureId.data(), config.captureId.size(), idInput, sizeof idInput);
    config.source = SourceInfo{ .format = "xicap", .formatVersion = std::format("{}.{}", reader.versionMajor(), reader.versionMinor()), .sourceHash = options.sourceHash, .metadata = options.metadata };

    Writer          writer{ dst, std::move(config), FramePolicy::archive() };
    internal::Scene scene;
    ReadPacket      packet{};
    uint64_t        index = 0;
    for (; index <= options.last && reader.next(packet); ++index)
    {
        if (index < options.first)
        {
            scene.add(index, packet);
            continue;
        }
        if (index == options.first)
        {
            // Stamped with the first packet's time, so a reader that does not know the flag still starts there.
            for (const auto& [_, kept] : scene.packets())
            {
                const auto& p = kept.first;
                writer.write({
                    .timestamp  = packet.timestamp,
                    .direction  = (p.flags & PacketFlag::ClientToServer) != 0 ? PacketDirection::ClientToServer : PacketDirection::ServerToClient,
                    .data       = std::as_bytes(std::span{ p.data }),
                    .channel    = p.channel,
                    .opcode     = p.opcode,
                    .provenance = static_cast<uint16_t>(p.flags | PacketFlag::Carried),
                });
            }
        }
        for (const auto& m : packet.markers)
        {
            internal::Access::marker(writer, m.kind, m.text);
        }
        writer.write({
            .timestamp  = packet.timestamp,
            .direction  = packet.direction,
            .data       = packet.data,
            .channel    = packet.channel,
            .opcode     = packet.opcode,
            .provenance = packet.flags,
        });
    }
    if (index <= options.last)
    {
        throw std::out_of_range(std::format("xicap: the capture holds {} packets, not {}", index, options.last + 1));
    }
    writer.close();
}

} // namespace xicap
