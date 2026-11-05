#include "xicap/transcode.h"
#include "xicap/reader.h"

#include <algorithm>
#include <format>

namespace xicap
{
namespace
{

auto same(const Packet& a, const Packet& b) -> bool
{
    return a.timestamp == b.timestamp && a.flags == b.flags && a.channel == b.channel && a.opcode == b.opcode &&
           std::ranges::equal(a.data, b.data) && std::ranges::equal(a.markers, b.markers);
}

auto compare(const std::filesystem::path& src, const std::filesystem::path& dst) -> void
{
    Reader a(src);
    Reader b(dst);
    if (a.metadata() != b.metadata())
    {
        throw Error("xicap: transcode changed the metadata");
    }

    Packet pa;
    Packet pb;
    for (uint64_t i{ 0 };; ++i)
    {
        const auto na = a.next(pa);
        const auto nb = b.next(pb);
        if (na != nb || (na && !same(pa, pb)))
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

auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, const FramePolicy policy) -> void
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
            Packet p;
            while (in.next(p))
            {
                out.copy(p);
            }

            out.close();
        }

        compare(src, dst);
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
