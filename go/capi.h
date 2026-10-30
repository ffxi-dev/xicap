#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        uint8_t  version_major;
        uint8_t  version_minor;
        char     capture_agent[32];
        char     client_version[32];
        char     character_name[16];
        char     world_name[16];
        uint16_t start_zone_id;
        uint16_t end_zone_id;
        uint64_t start_timestamp;
        uint64_t end_timestamp;
        uint64_t packets;
        uint64_t frames;
        int      closed;
    } xicap_summary;

    // Checks that data starts with a header this library can read.
    int xicap_check_header(const uint8_t* data, size_t size, char* err, size_t errlen);

    // Reads a whole capture, decoding every frame. A cut-off capture reads up to its last whole frame.
    int xicap_read(const char* path, xicap_summary* out, char* err, size_t errlen);

    // Reports whether two headers differ only in the fields the writer fills in after writing the header.
    int xicap_same_except_patched(const uint8_t* a, const uint8_t* b);

#ifdef __cplusplus
}
#endif
