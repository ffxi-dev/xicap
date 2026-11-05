#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// What cgo calls. A function that can fail returns NULL, or an error message for the caller to free. Pointers a reader
// hands out point into it: metadata until it closes, a packet until the next call.
#define XICAP_HEADER_SIZE 160

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        uint8_t        capture_id[16];
        uint8_t        previous_capture_id[16];
        uint64_t       start_timestamp;
        uint8_t        origin;
        uint8_t        server_kind;
        const char*    capture_agent;
        const char*    client_version;
        uint32_t       content_id;
        uint32_t       character_id;
        const char*    character_name;
        const char*    world_name;
        bool           has_source;
        const char*    source_format;
        const char*    source_format_version;
        uint32_t       skipped_records;
        const uint8_t* source_metadata;
        size_t         source_metadata_size;
    } xicap_metadata;

    typedef struct
    {
        xicap_metadata metadata;
        bool           complete;
        uint64_t       end_timestamp;
        uint64_t       packet_count;
    } xicap_info;

    typedef struct
    {
        uint8_t     kind;
        const char* text;
        size_t      text_size;
    } xicap_marker;

    typedef struct
    {
        uint64_t            timestamp;
        uint16_t            flags;
        uint8_t             channel;
        uint16_t            opcode;
        const uint8_t*      data;
        size_t              size;
        const xicap_marker* markers;
        size_t              marker_count;
    } xicap_packet;

    typedef struct
    {
        uint64_t       timestamp;
        bool           client_to_server;
        uint16_t       provenance;
        uint8_t        channel;
        uint16_t       opcode;
        const uint8_t* data;
        size_t         size;
    } xicap_write_packet;

    typedef struct xicap_reader xicap_reader;
    typedef struct xicap_writer xicap_writer;

    char* xicap_check_header(const uint8_t* data, size_t size);

    char* xicap_reader_open(const char* path, xicap_reader** out, xicap_info* info);
    // Sets *more to false at the end of the capture.
    char* xicap_reader_next(xicap_reader* r, xicap_packet* out, bool* more);
    void  xicap_reader_close(xicap_reader* r);

    // Sets capture_id to the capture's id, which the writer picks when metadata's is all zero.
    char* xicap_writer_open(const char* path, const xicap_metadata* metadata, bool keep_chat, bool archive, xicap_writer** out, uint8_t capture_id[16]);
    char* xicap_writer_write(xicap_writer* w, const xicap_write_packet* packet);
    // Frees the writer, even when closing fails.
    char* xicap_writer_close(xicap_writer* w);

    char* xicap_transcode(const char* src, const char* dst);

#ifdef __cplusplus
}
#endif
