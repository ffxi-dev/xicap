#include "xicap/reader.h"
#include "bytes/crc32.h"
#include "format/layout.h"

#include <array>
#include <format>

namespace xicap
{

Reader::Reader(const std::filesystem::path& path)
: file_(path, std::ios::binary)
, chunk_(64 * 1024)
{
    if (!file_)
    {
        throw Error("xicap: cannot open " + path.string());
    }

    // A valid trailer at the end makes the file complete; a bad frame then refuses it, rather than ending it.
    const auto size = std::filesystem::file_size(path);
    if (size >= sizeof(format::Header) + sizeof(format::Trailer))
    {
        std::array<uint8_t, sizeof(format::Trailer)> raw{};
        file_.seekg(static_cast<std::streamoff>(size - raw.size()));
        file_.read(reinterpret_cast<char*>(raw.data()), raw.size());
        const auto t = bytes::load<format::Trailer>(std::span{ raw });
        complete_    = file_ && t.magic == format::TRAILER_MAGIC && bytes::endsWithCrc(raw);
        if (complete_)
        {
            endTimestamp_ = t.endTimestamp;
            packetCount_  = t.packetCount;
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
            return false;
        }

        if (stream_.stopped() || !pushChunk())
        {
            if (complete_)
            {
                throw Error(std::format("xicap: bad frame at byte {}", stream_.bytesRead()));
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
