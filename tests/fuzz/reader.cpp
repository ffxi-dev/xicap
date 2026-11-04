#include <xicap/stream_reader.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

// Feeds the input in two pushes, split by its first byte, so partial frames are exercised too.
extern "C" auto LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) -> int
{
    if (size == 0)
    {
        return 0;
    }

    const auto bytes = std::as_bytes(std::span{ data, size });
    const auto split = std::min<size_t>(data[0] * 64, size);
    try
    {
        xicap::StreamReader s;
        s.push(bytes.first(split));
        xicap::Packet p;
        while (s.next(p))
        {
        }

        s.push(bytes.subspan(split));
        while (s.next(p))
        {
        }
    }
    catch (const xicap::Error&)
    {
    }

    return 0;
}
