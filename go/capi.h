#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        uint8_t  channel;
        uint8_t  direction; // 0 to the client, 1 from the client, 2 both
        uint8_t  action;    // 1 stub, 2 zero byte ranges
        uint16_t opcode;
        uint16_t range_count;
    } xicap_rule;

    typedef struct
    {
        uint32_t offset;
        uint32_t length; // 0xFFFFFFFF runs to the packet's end
    } xicap_range;

#define XICAP_SUMMARY_RULES 256

    typedef struct
    {
        uint8_t    version_major;
        uint8_t    version_minor;
        char       capture_agent[32];
        char       client_version[32];
        uint8_t    capture_id[16];
        uint8_t    previous_capture_id[16];
        uint32_t   content_id;
        uint32_t   character_id;
        uint16_t   world_id;
        char       character_name[16];
        char       world_name[16];
        uint8_t    clock_source;
        uint8_t    origin;
        uint8_t    network;
        uint8_t    start_context;
        uint16_t   start_zone_id; // first packet frame's zone
        uint16_t   end_zone_id;   // last packet frame's zone
        uint64_t   start_timestamp;
        uint64_t   end_timestamp; // last packet read
        uint64_t   packets;
        uint64_t   frames; // packet frames
        int        complete;
        int        footer_damaged;
        int        character_mismatch;
        uint64_t   unread_bytes;
        char       policy_name[32];
        uint32_t   policy_version;
        uint32_t   rule_count;     // may exceed XICAP_SUMMARY_RULES; only that many are filled
        int        covers_default; // the policy removes at least what xicap's default policy does
        xicap_rule rules[XICAP_SUMMARY_RULES];
        int        has_source;
        char       source_format[16];
        char       source_format_version[16];
        uint32_t   skipped_records;
        int        has_source_signer; // the source was a signed capture
        uint8_t    source_signing_key[32];
        int        source_signed_to_end;
        uint64_t   source_verified_packets;
        uint8_t    channels[32]; // bit c of byte c/8: a packet on channel c
        uint8_t    signing_key[32];
        int        signed_to_end;
        uint64_t   verified_packets;
        uint64_t   first_failure; // file offset of the first signature that fails; 0 when none does
        // The seal of a program that rewrote the file.
        int      sealed;
        int      seal_ok;
        uint8_t  seal_key[32];
        char     seal_agent[32];
        uint64_t sealed_at; // Unix ms
    } xicap_summary;

    // The length of the header data starts with, from its first 12 bytes, or -1.
    int xicap_header_size(const uint8_t* data, size_t size);

    // Checks that data starts with a whole header this library can read.
    int xicap_check_header(const uint8_t* data, size_t size, char* err, size_t errlen);

    // The action (1 stub, 2 zero byte ranges) of the first rule matching a packet, as the writer picks it; 0 when none matches.
    uint8_t xicap_policy_action(const xicap_rule* rules, size_t rule_count, uint8_t channel, uint8_t direction, uint16_t opcode);

    // Reads a whole capture, decoding every frame and checking its signatures.
    // A cut-off capture reads up to its last intact frame.
    int xicap_read(const char* path, xicap_summary* out, char* err, size_t errlen);

    typedef struct
    {
        uint8_t  kind; // 0 note, 1 login, 2 logout
        char*    text; // text_size bytes, then a NUL; the text itself may hold NULs
        size_t   text_size;
        uint64_t packet;    // index of the packet the marker precedes
        uint64_t timestamp; // that packet's, Unix ms
    } xicap_marker;

    // Reads every marker of a capture, in order; a cut-off capture up to its last intact frame. Free the result with xicap_free_markers.
    int  xicap_markers(const char* path, xicap_marker** out, size_t* count, char* err, size_t errlen);
    void xicap_free_markers(xicap_marker* markers, size_t count);

    typedef struct xicap_writer xicap_writer;

    typedef struct
    {
        const char* capture_agent;
        const char* client_version;
        uint32_t    content_id;
        uint32_t    character_id;
        uint16_t    world_id;
        const char* character_name;
        const char* world_name;
        uint8_t     clock_source;
        uint8_t     origin;
        uint8_t     network;
        uint8_t     start_context;
        uint8_t     previous_capture_id[16];
        uint8_t     signing_seed[32];
        int         preset; // 0 live, 1 archive
        int         level;  // zstd level; 0 for the preset's. Another level takes its own match table
        // Exclusion policy; without one the writer uses the default. Each rule
        // takes its range_count ranges from ranges, in order.
        int                has_policy;
        const char*        policy_name;
        uint32_t           policy_version;
        const xicap_rule*  rules;
        size_t             rule_count;
        const xicap_range* ranges;
        size_t             range_count;
        // Source of a converted capture (origin 2).
        int            has_source;
        const char*    source_format;
        const char*    source_format_version;
        uint32_t       skipped_records;
        int32_t        utc_offset_seconds;
        uint8_t        source_hash[64];
        const uint8_t* metadata;
        size_t         metadata_size;
    } xicap_writer_info;

    // Creates a capture at path. Returns NULL and fills err on failure.
    xicap_writer* xicap_writer_open(const char* path, const xicap_writer_info* info, char* err, size_t errlen);

    // Adds a metadata block (type 0x8000 and up) before the first packet.
    int xicap_writer_add_extension(xicap_writer* w, uint32_t type, const uint8_t* data, size_t size, char* err, size_t errlen);

    // Adds one packet; timestamp is Unix ms. opcode is used off the game channel.
    int xicap_writer_write(xicap_writer* w, uint64_t timestamp, int client_to_server, uint8_t channel, uint16_t opcode, uint16_t provenance, const uint8_t* data, size_t size, char* err, size_t errlen);

    // Places a marker (0 note, 1 login, 2 logout) before the next packet.
    int xicap_writer_mark(xicap_writer* w, uint8_t kind, const char* text, size_t text_size, char* err, size_t errlen);

    int xicap_writer_flush(xicap_writer* w, char* err, size_t errlen);

    void xicap_writer_ids(const xicap_writer* w, uint8_t capture_id[16], uint8_t public_key[32]);

    // Writes the footer and frees the writer, even on error.
    int xicap_writer_close(xicap_writer* w, char* err, size_t errlen);

    typedef struct
    {
        int         seal;  // 1: keep the signer's signature and add a seal; 0: reissue, signed by the file's own signer
        int         level; // zstd level; 0 for the archive preset's 19
        const char* agent;
        uint8_t     seed[32];
        // Reissue: the source signer to write, when has_signer is set.
        int      has_signer;
        uint8_t  signer_key[32];
        int      signer_signed_to_end;
        uint64_t signer_verified_packets;
    } xicap_transcode_info;

    // Rewrites src at dst with the archive preset, then reads dst back and checks its packets, markers, and signatures
    // against src. On any difference it fails and leaves dst as it was.
    int xicap_transcode(const char* src, const char* dst, const xicap_transcode_info* info, char* err, size_t errlen);

#ifdef __cplusplus
}
#endif
