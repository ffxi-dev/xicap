#include "xicap/reader.h"
#include "format/layout.h"

#include <array>
#include <format>

namespace xicap
{

Reader::Reader(const std::filesystem::path& path)
: file_(path, std::ios::binary)
, chunk_(size_t{ 64 } * 1024)
{
    if (!file_)
    {
        throw Error("xicap: cannot open " + path.string());
    }

    std::error_code ec;
    const auto      size = std::filesystem::file_size(path, ec);
    if (ec)
    {
        throw Error("xicap: cannot read " + path.string());
    }

    if (size >= sizeof(format::Header) + sizeof(format::Trailer))
    {
        std::array<uint8_t, sizeof(format::Trailer)> raw{};
        file_.seekg(static_cast<std::streamoff>(size - raw.size()));
        file_.read(reinterpret_cast<char*>(raw.data()), raw.size());
        if (const auto t = format::readTrailer(raw); file_ && t)
        {
            complete_     = true;
            endTimestamp_ = t->endTimestamp;
            packetCount_  = t->packetCount;
        }

        file_.clear();
        file_.seekg(0);
    }

    while (!stream_.ready())
    {
        if (!pushChunk())
        {
            throw Error("xicap: the file ends inside its header or blocks");
        }
    }
}

auto Reader::pushChunk() -> bool
{
    file_.read(reinterpret_cast<char*>(chunk_.data()), static_cast<std::streamsize>(chunk_.size()));
    if (file_.bad())
    {
        throw Error("xicap: a read failed");
    }

    const auto n = static_cast<size_t>(file_.gcount());
    stream_.push(std::span{ chunk_ }.first(n));
    return n > 0;
}

auto Reader::next(Packet& packet) -> bool
{
    while (!stream_.next(packet))
    {
        if (stream_.complete())
        {
            pushChunk(); // the stream refuses bytes after the trailer
            return false;
        }

        if (stream_.stopped() || !pushChunk())
        {
            if (complete_)
            {
                const auto why = stream_.stopped() ? stream_.stopReason() : std::string_view{ "xicap: the file ends inside a frame" };
                throw Error(std::format("{} (at byte {})", why, stream_.bytesRead()));
            }

            return false;
        }
    }

    return true;
}

Reader::Iterator::Iterator(Reader& reader)
: reader_(&reader)
{
    ++*this;
}

auto Reader::Iterator::operator++() -> Iterator&
{
    done_ = !reader_->next(packet_);
    return *this;
}

} // namespace xicap
