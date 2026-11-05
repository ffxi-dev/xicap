#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// What cgo calls. A function that can fail returns NULL, or an error message for the caller to free.
#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        uint8_t  kind;
        char*    text;
        size_t   text_size;
        uint64_t packet;
        uint64_t timestamp;
    } xicap_marker;

    // Text arrays are as wide as the fields FORMAT.md gives them.
    typedef struct
    {
        uint8_t       capture_id[16];
        uint8_t       previous_capture_id[16];
        uint64_t      start_timestamp;
        uint8_t       origin;
        uint8_t       network;
        char          capture_agent[32];
        char          client_version[32];
        uint32_t      content_id;
        uint32_t      character_id;
        char          character_name[16];
        char          world_name[16];
        char          policy_name[32];
        uint32_t      policy_version;
        uint32_t      policy_rules;
        bool          has_source;
        char          source_format[16];
        char          source_format_version[16];
        uint32_t      skipped_records;
        uint8_t*      source_metadata;
        size_t        source_metadata_size;
        uint64_t      end_timestamp;
        uint64_t      packet_count;
        bool          complete;
        bool          channels[256];
        xicap_marker* markers;
        size_t        marker_count;
    } xicap_summary;

    typedef struct
    {
        const char*    capture_agent;
        const char*    client_version;
        uint32_t       content_id;
        uint32_t       character_id;
        const char*    character_name;
        const char*    world_name;
        uint8_t        origin;
        uint8_t        network;
        bool           has_source;
        const char*    source_format;
        const char*    source_format_version;
        uint32_t       skipped_records;
        const uint8_t* source_metadata;
        size_t         source_metadata_size;
        bool           keep_chat;
        bool           archive;
    } xicap_writer_info;

    typedef struct xicap_writer xicap_writer;

    char* xicap_check_header(const uint8_t* data, size_t size);
    char* xicap_read(const char* path, xicap_summary* out);
    void  xicap_free_summary(xicap_summary* summary);

    char* xicap_writer_open(const char* path, const xicap_writer_info* info, xicap_writer** out);
    char* xicap_writer_write(xicap_writer* w, uint64_t timestamp, bool client_to_server, uint8_t channel, uint16_t opcode, uint16_t provenance, const uint8_t* data, size_t size);
    // Frees the writer, even when closing fails.
    char* xicap_writer_close(xicap_writer* w);

    char* xicap_transcode(const char* src, const char* dst);

#ifdef __cplusplus
}
#endif
