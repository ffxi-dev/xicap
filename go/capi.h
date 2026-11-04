#pragma once

#include <stddef.h>
#include <stdint.h>

// The C interface cgo calls. Each call that can fail returns 0, or -1 with a message in err.
#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        uint8_t  kind;
        char*    text;
        size_t   text_size;
        uint64_t packet;    // the index of the packet it sits before
        uint64_t timestamp; // that packet's
    } xicap_marker;

    typedef struct
    {
        uint8_t       capture_id[16];
        uint8_t       previous_capture_id[16];
        uint64_t      start_timestamp;
        uint64_t      end_timestamp; // the last packet read
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
        int           has_source;
        char          source_format[16];
        char          source_format_version[16];
        uint32_t      skipped_records;
        uint8_t*      source_metadata;
        size_t        source_metadata_size;
        uint64_t      packets;
        int           complete;
        uint8_t       channels[32]; // bit c of byte c/8: a packet on channel c
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
        int            has_source;
        const char*    source_format;
        const char*    source_format_version;
        uint32_t       skipped_records;
        const uint8_t* source_metadata;
        size_t         source_metadata_size;
        int            keep_chat; // no exclusion rules: chat stays
        int            archive;   // the archive frame policy
    } xicap_writer_info;

    typedef struct xicap_writer xicap_writer;

    int  xicap_check_header(const uint8_t* data, size_t size, char* err, size_t errlen);
    int  xicap_read(const char* path, xicap_summary* out, char* err, size_t errlen);
    void xicap_free_summary(xicap_summary* summary);

    xicap_writer* xicap_writer_open(const char* path, const xicap_writer_info* info, char* err, size_t errlen);
    int           xicap_writer_write(xicap_writer* w, uint64_t timestamp, int client_to_server, uint8_t channel, uint16_t opcode, uint16_t provenance, const uint8_t* data, size_t size, char* err, size_t errlen);
    // Frees the writer whether or not closing succeeds.
    int xicap_writer_close(xicap_writer* w, char* err, size_t errlen);

    int xicap_transcode(const char* src, const char* dst, char* err, size_t errlen);

#ifdef __cplusplus
}
#endif
