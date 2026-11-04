// libFuzzer target for the format-4 column decoder. The first 6 bytes give the packet and marker counts; the rest is
// a frame's plaintext. Build with clang and -fsanitize=fuzzer,address:
//
//   clang++ -std=c++23 -g -O1 -fsanitize=fuzzer,address -Iinclude -Isrc tests/fuzz_columns.cpp src/columns.cpp

#include "internal/columns.h"
#include "xicap/constants.h"

#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 6)
    {
        return 0;
    }
    uint32_t packets = 0;
    uint16_t markers = 0;
    std::memcpy(&packets, data, 4);
    std::memcpy(&markers, data + 4, 2);
    xicap::internal::DecodedFrame frame;
    try
    {
        xicap::internal::decodeColumns({ data + 6, size - 6 }, packets % (xicap::FrameLimits::MAX_PACKETS + 1), markers, 0, frame);
    }
    catch (const xicap::Error&)
    {
    }
    return 0;
}
