#include "columns.h"

#include <cstddef>
#include <cstdint>
#include <span>

// The plaintext decoder behind zstd and the frame CRC, which random input rarely gets past. The first 4 bytes give
// the packet and marker counts.
extern "C" auto LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) -> int
{
    if (size < 4)
    {
        return 0;
    }
    const uint32_t packets = data[0] | (data[1] << 8);
    const uint32_t markers = data[2] | (data[3] << 8);
    try
    {
        xicap::internal::DecodedFrame frame;
        xicap::internal::decodeColumns({ data + 4, size - 4 }, packets, markers, 0, frame);
    }
    catch (const xicap::Error&)
    {
    }
    return 0;
}
