#include <xicap/xicap.h>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl/filesystem.h>

#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace py = pybind11;

namespace
{

template <typename T>
auto toBytes(const T& bytes) -> py::bytes
{
    return py::bytes(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

template <size_t N>
auto text(const std::array<char, N>& field) -> std::string
{
    return { field.data(), ::strnlen(field.data(), N) };
}

// Marker text should be UTF-8, but a recorder may have stored other bytes, such as Shift-JIS; each reads as U+FFFD
// instead of failing the packet.
auto utf8(const std::string& text) -> py::str
{
    PyObject* s = PyUnicode_DecodeUTF8(text.data(), static_cast<Py_ssize_t>(text.size()), "replace");
    if (s == nullptr)
    {
        throw py::error_already_set();
    }
    return py::reinterpret_steal<py::str>(s);
}

// A packet that owns its bytes: a ReadPacket's spans go stale on the reader's next call.
struct Packet
{
    uint64_t               timestampMs;
    uint8_t                channel;
    uint16_t               opcode;
    uint16_t               flags;
    xicap::PacketDirection direction;
    py::bytes              data;
    py::list               markers; // (MarkerKind, text) tuples
};

auto next(xicap::Reader& reader) -> std::optional<Packet>
{
    xicap::ReadPacket p{};
    if (!reader.next(p))
    {
        return std::nullopt;
    }
    py::list markers;
    for (const auto& m : p.markers)
    {
        markers.append(py::make_tuple(m.kind, utf8(m.text)));
    }
    return Packet{
        .timestampMs = p.timestamp,
        .channel     = p.channel,
        .opcode      = p.opcode,
        .flags       = p.flags,
        .direction   = p.direction,
        .data        = toBytes(p.data),
        .markers     = std::move(markers),
    };
}

auto character(const xicap::Reader& reader) -> py::dict
{
    const auto& c = reader.character();
    py::dict    out;
    out["contentId"]     = c.contentId;
    out["characterId"]   = c.characterId;
    out["worldId"]       = c.worldId;
    out["characterName"] = text(c.characterName);
    out["worldName"]     = text(c.worldName);
    return out;
}

auto policy(const xicap::Reader& reader) -> py::dict
{
    const auto& p = reader.policy();
    py::list    rules;
    for (const auto& r : p.rules)
    {
        py::list ranges;
        for (const auto& range : r.ranges)
        {
            ranges.append(py::make_tuple(range.offset, range.length));
        }
        py::dict rule;
        rule["channel"]   = r.channel;
        rule["direction"] = static_cast<int>(r.direction);
        rule["action"]    = static_cast<int>(r.action);
        rule["opcode"]    = r.opcode;
        rule["ranges"]    = ranges;
        rules.append(rule);
    }
    py::dict out;
    out["name"]    = p.name;
    out["version"] = p.version;
    out["rules"]   = rules;
    return out;
}

auto source(const xicap::Reader& reader) -> py::object
{
    const auto& s = reader.source();
    if (!s)
    {
        return py::none();
    }
    py::dict out;
    out["format"]           = s->format;
    out["formatVersion"]    = s->formatVersion;
    out["skippedRecords"]   = s->skippedRecords;
    out["utcOffsetSeconds"] = s->utcOffsetSeconds;
    out["sourceHash"]       = toBytes(s->sourceHash);
    out["metadata"]         = toBytes(s->metadata);
    return out;
}

auto verify(xicap::Reader& reader) -> py::dict
{
    const auto v = reader.verify();
    py::dict   out;
    out["key"]                = toBytes(v.key);
    out["signedToEnd"]        = v.signedToEnd;
    out["verifiedPackets"]    = v.verifiedPackets;
    out["goodCheckpoints"]    = v.goodCheckpoints;
    out["firstFailureOffset"] = v.firstFailureOffset ? py::cast(*v.firstFailureOffset) : py::none();
    out["seal"]               = py::none();
    if (v.seal)
    {
        py::dict seal;
        seal["key"]        = toBytes(v.seal->key);
        seal["agent"]      = v.seal->agent;
        seal["sealedAtMs"] = v.seal->sealedAt;
        seal["good"]       = v.seal->good;
        out["seal"]        = seal;
    }
    return out;
}

auto skippedRegions(const xicap::Reader& reader) -> py::list
{
    py::list out;
    for (const auto& r : reader.skippedRegions())
    {
        out.append(py::make_tuple(r.offset, r.length));
    }
    return out;
}

auto extensionTypes(const xicap::Reader& reader) -> std::vector<uint32_t>
{
    std::vector<uint32_t> types;
    for (const auto& e : reader.extensions())
    {
        types.push_back(e.type);
    }
    return types;
}

auto getExtension(const xicap::Reader& reader, uint32_t type) -> std::optional<py::bytes>
{
    const auto* ext = reader.getExtension(type);
    if (ext == nullptr)
    {
        return std::nullopt;
    }
    return toBytes(ext->data);
}

auto listZones(const xicap::Reader& reader) -> py::list
{
    py::list out;
    for (const auto& z : reader.listZones())
    {
        py::dict d;
        d["zoneId"]      = z.zoneId;
        d["timestampMs"] = z.timestamp;
        d["fileOffset"]  = z.fileOffset;
        out.append(d);
    }
    return out;
}

auto transcode(const std::filesystem::path& src, const std::filesystem::path& dst, const py::bytes& seed, const std::string& agent, int level) -> py::dict
{
    xicap::TranscodeOptions options{};
    options.agent    = agent;
    const auto bytes = static_cast<std::string_view>(seed);
    if (bytes.size() != options.seed.size())
    {
        throw py::value_error("seed must be 32 bytes");
    }
    std::memcpy(options.seed.data(), bytes.data(), options.seed.size());
    if (level != 0)
    {
        options.policy.compressionLevel = level;
    }
    xicap::TranscodeResult r;
    {
        py::gil_scoped_release release;
        r = xicap::transcode(src, dst, options);
    }
    py::dict out;
    out["packets"]  = r.packets;
    out["markers"]  = r.markers;
    out["bytesIn"]  = r.bytesIn;
    out["bytesOut"] = r.bytesOut;
    return out;
}

} // namespace

PYBIND11_MODULE(_xicap, m)
{
    m.doc() = "Native bindings for the xicap reader.";

    py::enum_<xicap::PacketDirection>(m, "PacketDirection")
        .value("ServerToClient", xicap::PacketDirection::ServerToClient)
        .value("ClientToServer", xicap::PacketDirection::ClientToServer);

    py::enum_<xicap::MarkerKind>(m, "MarkerKind")
        .value("Note", xicap::MarkerKind::Note)
        .value("Login", xicap::MarkerKind::Login)
        .value("Logout", xicap::MarkerKind::Logout);

    py::enum_<xicap::ClockSource>(m, "ClockSource")
        .value("Unknown", xicap::ClockSource::Unknown)
        .value("Live", xicap::ClockSource::Live)
        .value("Converted", xicap::ClockSource::Converted);

    py::enum_<xicap::Origin>(m, "Origin")
        .value("Unknown", xicap::Origin::Unknown)
        .value("Live", xicap::Origin::Live)
        .value("Converted", xicap::Origin::Converted);

    py::enum_<xicap::Network>(m, "Network")
        .value("Unknown", xicap::Network::Unknown)
        .value("Retail", xicap::Network::Retail)
        .value("Private", xicap::Network::Private);

    py::enum_<xicap::StartContext>(m, "StartContext")
        .value("Unknown", xicap::StartContext::Unknown)
        .value("Login", xicap::StartContext::Login)
        .value("MidSession", xicap::StartContext::MidSession);

    py::enum_<xicap::SeekResult>(m, "SeekResult")
        .value("Ok", xicap::SeekResult::Ok)
        .value("EmptyIndex", xicap::SeekResult::EmptyIndex)
        .value("OutOfRange", xicap::SeekResult::OutOfRange)
        .value("NotFound", xicap::SeekResult::NotFound);

    py::enum_<xicap::ErrorCode>(m, "ErrorCode")
        .value("OpenFailed", xicap::ErrorCode::OpenFailed)
        .value("BadMagic", xicap::ErrorCode::BadMagic)
        .value("UnsupportedVersion", xicap::ErrorCode::UnsupportedVersion)
        .value("DictionaryMismatch", xicap::ErrorCode::DictionaryMismatch)
        .value("ShortHeader", xicap::ErrorCode::ShortHeader)
        .value("ShortExtension", xicap::ErrorCode::ShortExtension)
        .value("ExtensionTooLarge", xicap::ErrorCode::ExtensionTooLarge)
        .value("CorruptFrame", xicap::ErrorCode::CorruptFrame)
        .value("FrameChecksumMismatch", xicap::ErrorCode::FrameChecksumMismatch)
        .value("DecompressFailed", xicap::ErrorCode::DecompressFailed)
        .value("ZstdContextFailed", xicap::ErrorCode::ZstdContextFailed)
        .value("WriterClosed", xicap::ErrorCode::WriterClosed)
        .value("AddExtensionAfterPackets", xicap::ErrorCode::AddExtensionAfterPackets)
        .value("AddMarkerWithoutPacket", xicap::ErrorCode::AddMarkerWithoutPacket)
        .value("PacketTooLarge", xicap::ErrorCode::PacketTooLarge)
        .value("CompressFailed", xicap::ErrorCode::CompressFailed)
        .value("HeaderChecksumMismatch", xicap::ErrorCode::HeaderChecksumMismatch)
        .value("ExtensionChecksumMismatch", xicap::ErrorCode::ExtensionChecksumMismatch)
        .value("MissingPolicy", xicap::ErrorCode::MissingPolicy)
        .value("UnknownFrameKind", xicap::ErrorCode::UnknownFrameKind)
        .value("UnknownPacketFlag", xicap::ErrorCode::UnknownPacketFlag)
        .value("InvalidPolicy", xicap::ErrorCode::InvalidPolicy)
        .value("InvalidExtension", xicap::ErrorCode::InvalidExtension)
        .value("WriteFailed", xicap::ErrorCode::WriteFailed)
        .value("PacketTooShort", xicap::ErrorCode::PacketTooShort)
        .value("TranscodeRefused", xicap::ErrorCode::TranscodeRefused)
        .value("TranscodeMismatch", xicap::ErrorCode::TranscodeMismatch);

    // xicap::Error becomes a Python exception with a .code attribute.
    static py::exception<xicap::Error> errExc(m, "Error");
    py::register_exception_translator([](std::exception_ptr p)
                                      {
                                          try
                                          {
                                              if (p)
                                              {
                                                  std::rethrow_exception(p);
                                              }
                                          }
                                          catch (const xicap::Error& e)
                                          {
                                              // py::exception's call operator sets no attributes: build the instance.
                                              py::object inst = py::reinterpret_steal<py::object>(PyObject_CallFunction(errExc.ptr(), "s", e.what()));
                                              if (inst)
                                              {
                                                  inst.attr("code") = py::cast(e.code());
                                                  PyErr_SetObject(errExc.ptr(), inst.ptr());
                                              }
                                          }
                                      });

    py::class_<Packet>(m, "Packet")
        .def_readonly("timestampMs", &Packet::timestampMs)
        .def_readonly("channel", &Packet::channel)
        .def_readonly("opcode", &Packet::opcode)
        .def_readonly("flags", &Packet::flags)
        .def_readonly("direction", &Packet::direction)
        .def_readonly("data", &Packet::data)
        .def_readonly("markers", &Packet::markers);

    using xicap::Reader;
    py::class_<Reader>(m, "Reader")
        .def(py::init([](const std::filesystem::path& path, bool recovery)
                      {
                          return std::make_unique<Reader>(path, xicap::ReaderOptions{ .recovery = recovery });
                      }),
             py::arg("path"),
             py::arg("recovery") = false)
        .def("next", &next)
        .def("skip_current_frame", &Reader::skipCurrentFrame)
        .def("reset", &Reader::reset)
        .def("seek_to_frame", &Reader::seekToFrame)
        .def("seek_to_time", &Reader::seekToTime)
        .def("seek_to_zone", &Reader::seekToZone)
        .def("verify", &verify)
        .def_property_readonly("version_major", &Reader::versionMajor)
        .def_property_readonly("version_minor", &Reader::versionMinor)
        .def_property_readonly("client_version", &Reader::clientVersion)
        .def_property_readonly("capture_agent", &Reader::captureAgent)
        .def_property_readonly("capture_id", [](const Reader& r)
                               {
                                   return toBytes(r.captureId());
                               })
        .def_property_readonly("previous_capture_id", [](const Reader& r)
                               {
                                   return toBytes(r.previousCaptureId());
                               })
        .def_property_readonly("signing_key", [](const Reader& r)
                               {
                                   return toBytes(r.signingKey());
                               })
        .def_property_readonly("clock_source", &Reader::clockSource)
        .def_property_readonly("origin", &Reader::origin)
        .def_property_readonly("network", &Reader::network)
        .def_property_readonly("start_context", &Reader::startContext)
        .def_property_readonly("start_timestamp_ms", &Reader::startTimestamp)
        .def_property_readonly("end_timestamp_ms", &Reader::endTimestamp)
        .def_property_readonly("duration_ms", &Reader::durationMs)
        .def_property_readonly("total_frames", &Reader::totalFrames)
        .def_property_readonly("total_packet_count", &Reader::totalPacketCount)
        .def_property_readonly("complete", &Reader::complete)
        .def_property_readonly("footer_damaged", &Reader::footerDamaged)
        .def_property_readonly("character_mismatch", &Reader::characterMismatch)
        .def_property_readonly("unread_bytes", &Reader::unreadBytes)
        .def_property_readonly("character", &character)
        .def_property_readonly("policy", &policy)
        .def_property_readonly("source", &source)
        .def("skipped_regions", &skippedRegions)
        .def("extension_types", &extensionTypes)
        .def("get_extension", &getExtension, py::arg("type"))
        .def("list_zones", &listZones);

    m.def("transcode",
          &transcode,
          py::arg("src"),
          py::arg("dst"),
          py::kw_only(),
          py::arg("seed"),
          py::arg("agent"),
          py::arg("level") = 0,
          "Rewrites src at dst with the archive preset and checks it against src: it keeps the signer's signatures and "
          "adds a seal made with seed.");
}
