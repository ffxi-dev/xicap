#include "capi.h"

#include "xicap/reader.h"
#include "xicap/writer.h"

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <exception>

namespace
{

template <size_t N, size_t M>
void copyString(char (&dst)[N], const std::array<char, M>& src)
{
    const auto n = std::min(strnlen(src.data(), M), N - 1);
    std::memcpy(dst, src.data(), n);
    dst[n] = '\0';
}

void setError(char* err, size_t errlen, const char* message)
{
    std::snprintf(err, errlen, "%s", message);
}

} // namespace

extern "C" int xicap_check_header(const uint8_t* data, size_t size, char* err, size_t errlen)
{
    xicap::Header header{};
    if (size < sizeof(header))
    {
        setError(err, errlen, "xicap: short header");
        return -1;
    }
    std::memcpy(&header, data, sizeof(header));
    if (header.magic != xicap::MAGIC)
    {
        setError(err, errlen, "xicap: bad magic");
        return -1;
    }
    if (header.versionMajor != xicap::VERSION_MAJOR)
    {
        setError(err, errlen, "xicap: unsupported version");
        return -1;
    }
    return 0;
}

extern "C" int xicap_read(const char* path, xicap_summary* out, char* err, size_t errlen)
{
    try
    {
        xicap::Reader reader{ path };
        *out               = {};
        out->version_major = reader.versionMajor();
        out->version_minor = reader.versionMinor();
        std::snprintf(out->capture_agent, sizeof(out->capture_agent), "%s", reader.captureAgent().c_str());
        std::snprintf(out->client_version, sizeof(out->client_version), "%s", reader.clientVersion().c_str());
        copyString(out->character_name, reader.lobby().characterName);
        copyString(out->world_name, reader.lobby().worldName);
        out->start_zone_id   = reader.startZoneId();
        out->start_timestamp = reader.startTimestamp();
        out->end_timestamp   = out->start_timestamp;

        xicap::ReadPacket packet{};
        while (reader.next(packet))
        {
            out->packets++;
            out->end_timestamp = packet.timestamp;
        }

        const auto zones = reader.listZones();
        out->end_zone_id = zones.empty() ? reader.startZoneId() : zones.back().zoneId;
        out->frames      = reader.totalFrames();
        out->closed      = reader.hasFooter() ? 1 : 0;
        return 0;
    }
    catch (const std::exception& e)
    {
        setError(err, errlen, e.what());
        return -1;
    }
}

extern "C" int xicap_same_except_patched(const uint8_t* a, const uint8_t* b)
{
    xicap::Header x{};
    xicap::Header y{};
    std::memcpy(&x, a, sizeof(x));
    std::memcpy(&y, b, sizeof(y));
    for (auto* h : { &x, &y })
    {
        h->startTimestamp   = 0;
        h->endTimestamp     = 0;
        h->totalPacketCount = 0;
        h->endZoneId        = 0;
    }
    return std::memcmp(&x, &y, sizeof(x)) == 0 ? 1 : 0;
}

struct xicap_writer
{
    xicap::Writer writer;
};

extern "C" xicap_writer* xicap_writer_open(const char* path, const xicap_writer_info* info, char* err, size_t errlen)
{
    try
    {
        xicap::WriterConfig config{};
        config.captureAgent  = info->capture_agent;
        config.clientVersion = info->client_version;
        config.startZoneId   = info->start_zone_id;
        std::snprintf(config.lobby.characterName.data(), config.lobby.characterName.size(), "%s", info->character_name);
        return new xicap_writer{ xicap::Writer{ path, config } };
    }
    catch (const std::exception& e)
    {
        setError(err, errlen, e.what());
        return nullptr;
    }
}

extern "C" int xicap_writer_write(xicap_writer* w, uint64_t timestamp, int client_to_server, const uint8_t* data, size_t size, char* err, size_t errlen)
{
    try
    {
        const auto direction = client_to_server ? xicap::PacketDirection::ClientToServer : xicap::PacketDirection::ServerToClient;
        w->writer.write(timestamp, direction, std::span{ reinterpret_cast<const std::byte*>(data), size });
        return 0;
    }
    catch (const std::exception& e)
    {
        setError(err, errlen, e.what());
        return -1;
    }
}

extern "C" int xicap_writer_close(xicap_writer* w, char* err, size_t errlen)
{
    int rc = 0;
    try
    {
        w->writer.close();
    }
    catch (const std::exception& e)
    {
        setError(err, errlen, e.what());
        rc = -1;
    }
    delete w;
    return rc;
}
