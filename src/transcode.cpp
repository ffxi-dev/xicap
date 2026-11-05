#include "xicap/transcode.h"
#include "staged.h"
#include "xicap/reader.h"

#include <algorithm>
#include <format>
#include <optional>

namespace xicap
{
namespace
{

auto same(const Packet& a, const Packet& b) -> bool
{
    return a.timestamp == b.timestamp && a.flags == b.flags && a.channel == b.channel && a.opcode == b.opcode &&
           std::ranges::equal(a.data, b.data) && std::ranges::equal(a.markers, b.markers);
}

// Reads both files side by side; throws Error at the first difference.
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
    for (uint64_t i = 0;; ++i)
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

auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, FramePolicy policy) -> void
{
    const internal::Staged tmp(dst);
    {
        Reader in(src);
        Writer out(tmp.path(), in.metadata(), policy);
        Packet p;
        while (in.next(p))
        {
            out.copy(p);
        }

        out.close();
    }

    compare(src, tmp.path());
    tmp.publish();
}

auto continueFrom(const std::filesystem::path& source, uint64_t fromByte, const std::filesystem::path& out, FramePolicy policy) -> uint64_t
{
    Reader in(source);
    auto   metadata            = in.metadata();
    metadata.previousCaptureId = metadata.captureId;
    metadata.captureId         = {};
    const internal::Staged tmp(out);
    std::optional<Writer>  writer;
    uint64_t               packets = 0;
    Packet                 p;
    while (in.next(p))
    {
        if (in.bytesRead() <= fromByte)
        {
            continue;
        }

        if (!writer)
        {
            writer.emplace(tmp.path(), metadata, policy);
        }

        writer->copy(p);
        packets++;
    }

    if (!writer)
    {
        return 0;
    }

    writer->close();
    writer.reset();
    tmp.publish();
    return packets;
}

} // namespace xicap
