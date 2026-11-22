#include "xicap/transcode.h"
#include "xicap/reader.h"
#include "xicap/redaction.h"

#include <algorithm>
#include <format>
#include <vector>

namespace xicap
{
namespace
{

// p as a writer that does not keep chat holds it: its chat text zeroed, in buffer, and its redacted flag set.
auto redacted(const Packet& p, std::vector<uint8_t>& buffer) -> Packet
{
    if (p.channel != Channel::Game)
    {
        return p;
    }

    buffer.assign(p.data.begin(), p.data.end());
    if (!redact(buffer, p.direction()))
    {
        return p;
    }

    auto out = p;
    out.data = buffer;
    out.flags |= PacketFlag::Redacted;
    return out;
}

auto same(const Packet& a, const Packet& b) -> bool
{
    return a.timestamp == b.timestamp && a.flags == b.flags && a.channel == b.channel && a.opcode == b.opcode &&
           std::ranges::equal(a.data, b.data) && std::ranges::equal(a.markers, b.markers);
}

auto checkUnchanged(const std::filesystem::path& src, const std::filesystem::path& dst, const Chat chat) -> void
{
    Reader a(src);
    Reader b(dst);
    if (a.metadata() != b.metadata())
    {
        throw Error("xicap: transcode changed the metadata");
    }

    Packet               pa;
    Packet               pb;
    std::vector<uint8_t> buffer;
    for (uint64_t i{ 0 };; ++i)
    {
        const auto na = a.next(pa);
        const auto nb = b.next(pb);
        if (na != nb || (na && !same(chat == Chat::Redact ? redacted(pa, buffer) : pa, pb)))
        {
            throw Error(std::format("xicap: transcode changed packet {}", i));
        }

        if (!na)
        {
            return;
        }
    }
}

} // namespace

auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, const FramePolicy policy, const Chat chat) -> void
{
    std::error_code ec;
    if (std::filesystem::equivalent(src, dst, ec))
    {
        throw Error("xicap: transcode needs two different files");
    }

    auto opened = false;
    try
    {
        {
            Reader in(src);
            Writer out(dst, in.metadata(), policy);
            opened = true;
            Packet               p;
            std::vector<uint8_t> buffer;
            while (in.next(p))
            {
                out.copy(chat == Chat::Redact ? redacted(p, buffer) : p);
            }

            out.close();
        }

        checkUnchanged(src, dst, chat);
    }
    catch (...)
    {
        if (opened)
        {
            std::filesystem::remove(dst, ec);
        }

        throw;
    }
}

} // namespace xicap
