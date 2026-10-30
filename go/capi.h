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

    typedef struct xicap_writer xicap_writer;

    typedef struct
    {
        const char* capture_agent;
        const char* client_version;
        const char* character_name;
        uint16_t    start_zone_id;
    } xicap_writer_info;

    // Creates a capture at path. Returns NULL and fills err on failure.
    xicap_writer* xicap_writer_open(const char* path, const xicap_writer_info* info, char* err, size_t errlen);

    // Adds one packet; timestamp is Unix ms.
    int xicap_writer_write(xicap_writer* w, uint64_t timestamp, int client_to_server, const uint8_t* data, size_t size, char* err, size_t errlen);

    // Writes the footer and frees the writer, even on error.
    int xicap_writer_close(xicap_writer* w, char* err, size_t errlen);

#ifdef __cplusplus
}
#endif
