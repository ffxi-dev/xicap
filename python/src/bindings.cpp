#include <xicap/xicap.h>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl/filesystem.h>

#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
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

// One packet, owning its bytes: ReadPacket's spans point into Reader buffers
// that the next call invalidates.
struct PyPacket
{
    uint64_t               timestampMs;
    uint8_t                channel;
    uint16_t               opcode;
    uint16_t               flags;
    xicap::PacketDirection direction;
    py::bytes              data;
    py::list               markers; // (MarkerKind, text) tuples
};

class PyReader
{
public:
    PyReader(const std::filesystem::path& path, bool recovery)
    : reader_(std::make_unique<xicap::Reader>(path, xicap::ReaderOptions{ .recovery = recovery }))
    {
    }

    [[nodiscard]] auto next() -> std::optional<PyPacket>
    {
        if (!reader_->next(pkt_))
        {
            return std::nullopt;
        }
        py::list markers;
        for (const auto& m : pkt_.markers)
        {
            markers.append(py::make_tuple(m.kind, utf8(m.text)));
        }
        return PyPacket{
            .timestampMs = pkt_.timestamp,
            .channel     = pkt_.channel,
            .opcode      = pkt_.opcode,
            .flags       = pkt_.flags,
            .direction   = pkt_.direction,
            .data        = toBytes(pkt_.data),
            .markers     = std::move(markers),
        };
    }

    [[nodiscard]] auto reader() const -> xicap::Reader&
    {
        return *reader_;
    }

    [[nodiscard]] auto character() const -> py::dict
    {
        const auto& c = reader_->character();
        py::dict    out;
        out["contentId"]     = c.contentId;
        out["characterId"]   = c.characterId;
        out["worldId"]       = c.worldId;
        out["characterName"] = text(c.characterName);
        out["worldName"]     = text(c.worldName);
        return out;
    }

    [[nodiscard]] auto policy() const -> py::dict
    {
        const auto& p = reader_->policy();
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

    [[nodiscard]] auto source() const -> py::object
    {
        const auto& s = reader_->source();
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
        out["signer"]           = py::none();
        if (s->signer)
        {
            py::dict signer;
            signer["key"]             = toBytes(s->signer->key);
            signer["signedToEnd"]     = s->signer->signedToEnd;
            signer["verifiedPackets"] = s->signer->verifiedPackets;
            out["signer"]             = signer;
        }
        return out;
    }

    [[nodiscard]] auto verify() -> py::dict
    {
        const auto v = reader_->verify();
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

    [[nodiscard]] auto skippedRegions() const -> py::list
    {
        py::list out;
        for (const auto& r : reader_->skippedRegions())
        {
            out.append(py::make_tuple(r.offset, r.length));
        }
        return out;
    }

    [[nodiscard]] auto extensionTypes() const -> std::vector<uint32_t>
    {
        std::vector<uint32_t> types;
        for (const auto& e : reader_->extensions())
        {
            types.push_back(e.type);
        }
        return types;
    }

    [[nodiscard]] auto getExtension(uint32_t type) const -> std::optional<py::bytes>
    {
        const auto* ext = reader_->getExtension(type);
        return ext ? std::optional{ toBytes(ext->data) } : std::nullopt;
    }

    [[nodiscard]] auto listZones() const -> py::list
    {
        py::list out;
        for (const auto& z : reader_->listZones())
        {
            py::dict d;
            d["zoneId"]      = z.zoneId;
            d["timestampMs"] = z.timestamp;
            d["fileOffset"]  = z.fileOffset;
            out.append(d);
        }
        return out;
    }

private:
    std::unique_ptr<xicap::Reader> reader_;
    xicap::ReadPacket              pkt_{};
};

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
        .value("TranscodeMismatch", xicap::ErrorCode::TranscodeMismatch)
        .value("UnknownRecordingMode", xicap::ErrorCode::UnknownRecordingMode);

    py::enum_<xicap::RecordingMode>(m, "RecordingMode")
        .value("Default", xicap::RecordingMode::Default)
        .value("Everything", xicap::RecordingMode::Everything)
        .value("Anonymous", xicap::RecordingMode::Anonymous);

    // Map xicap::Error onto a Python exception with a .code attribute.
    static py::exception<xicap::Error> errExc(m, "Error");
    py::register_exception_translator([](std::exception_ptr p)
                                      {
                                          try
                                          {
                                              if (p)
                                                  std::rethrow_exception(p);
                                          }
                                          catch (const xicap::Error& e)
                                          {
                                              // py::exception::operator() returns void; construct the
                                              // instance by calling the exception type directly.
                                              py::object inst = py::reinterpret_steal<py::object>(
                                                  PyObject_CallFunction(errExc.ptr(), "s", e.what()));
                                              if (inst)
                                              {
                                                  inst.attr("code") = py::cast(e.code());
                                                  PyErr_SetObject(errExc.ptr(), inst.ptr());
                                              }
                                          }
                                      });

    py::class_<PyPacket>(m, "Packet")
        .def_readonly("timestampMs", &PyPacket::timestampMs)
        .def_readonly("channel", &PyPacket::channel)
        .def_readonly("opcode", &PyPacket::opcode)
        .def_readonly("flags", &PyPacket::flags)
        .def_readonly("direction", &PyPacket::direction)
        .def_readonly("data", &PyPacket::data)
        .def_readonly("markers", &PyPacket::markers);

    const auto r = [](auto f)
    {
        return [f](const PyReader& self)
        {
            return f(self.reader());
        };
    };

    py::class_<PyReader>(m, "Reader")
        .def(py::init<const std::filesystem::path&, bool>(), py::arg("path"), py::arg("recovery") = false)
        .def("next", &PyReader::next)
        .def("skip_current_frame", [](PyReader& self)
             {
                 self.reader().skipCurrentFrame();
             })
        .def("reset", [](PyReader& self)
             {
                 self.reader().reset();
             })
        .def("seek_to_frame", [](PyReader& self, uint64_t i)
             {
                 return self.reader().seekToFrame(i);
             })
        .def("seek_to_time", [](PyReader& self, uint64_t t)
             {
                 return self.reader().seekToTime(t);
             })
        .def("seek_to_zone", [](PyReader& self, uint16_t z)
             {
                 return self.reader().seekToZone(z);
             })
        .def("verify", &PyReader::verify)
        .def_property_readonly("version_major", r([](xicap::Reader& x)
                                                  {
                                                      return static_cast<int>(x.versionMajor());
                                                  }))
        .def_property_readonly("version_minor", r([](xicap::Reader& x)
                                                  {
                                                      return static_cast<int>(x.versionMinor());
                                                  }))
        .def_property_readonly("client_version", r([](xicap::Reader& x)
                                                   {
                                                       return x.clientVersion();
                                                   }))
        .def_property_readonly("capture_agent", r([](xicap::Reader& x)
                                                  {
                                                      return x.captureAgent();
                                                  }))
        .def_property_readonly("capture_id", r([](xicap::Reader& x)
                                               {
                                                   return toBytes(x.captureId());
                                               }))
        .def_property_readonly("previous_capture_id", r([](xicap::Reader& x)
                                                        {
                                                            return toBytes(x.previousCaptureId());
                                                        }))
        .def_property_readonly("signing_key", r([](xicap::Reader& x)
                                                {
                                                    return toBytes(x.signingKey());
                                                }))
        .def_property_readonly("clock_source", r([](xicap::Reader& x)
                                                 {
                                                     return x.clockSource();
                                                 }))
        .def_property_readonly("origin", r([](xicap::Reader& x)
                                           {
                                               return x.origin();
                                           }))
        .def_property_readonly("network", r([](xicap::Reader& x)
                                            {
                                                return x.network();
                                            }))
        .def_property_readonly("start_context", r([](xicap::Reader& x)
                                                  {
                                                      return x.startContext();
                                                  }))
        .def_property_readonly("start_timestamp_ms", r([](xicap::Reader& x)
                                                       {
                                                           return x.startTimestamp();
                                                       }))
        .def_property_readonly("end_timestamp_ms", r([](xicap::Reader& x)
                                                     {
                                                         return x.endTimestamp();
                                                     }))
        .def_property_readonly("duration_ms", r([](xicap::Reader& x)
                                                {
                                                    return x.durationMs();
                                                }))
        .def_property_readonly("total_frames", r([](xicap::Reader& x)
                                                 {
                                                     return x.totalFrames();
                                                 }))
        .def_property_readonly("total_packet_count", r([](xicap::Reader& x)
                                                       {
                                                           return x.totalPacketCount();
                                                       }))
        .def_property_readonly("complete", r([](xicap::Reader& x)
                                             {
                                                 return x.complete();
                                             }))
        .def_property_readonly("footer_damaged", r([](xicap::Reader& x)
                                                   {
                                                       return x.footerDamaged();
                                                   }))
        .def_property_readonly("character_mismatch", r([](xicap::Reader& x)
                                                       {
                                                           return x.characterMismatch();
                                                       }))
        .def_property_readonly("unread_bytes", r([](xicap::Reader& x)
                                                 {
                                                     return x.unreadBytes();
                                                 }))
        .def_property_readonly("character", &PyReader::character)
        .def_property_readonly("policy", &PyReader::policy)
        .def_property_readonly("source", &PyReader::source)
        .def("skipped_regions", &PyReader::skippedRegions)
        .def("extension_types", &PyReader::extensionTypes)
        .def("get_extension", &PyReader::getExtension, py::arg("type"))
        .def("list_zones", &PyReader::listZones);

    m.def(
        "transcode",
        [](const std::filesystem::path& src, const std::filesystem::path& dst, bool seal, const py::bytes& seed, const std::string& agent, int level, const py::object& signer)
        {
            const auto take = [](const py::bytes& b, auto& out, const char* what)
            {
                const auto view = static_cast<std::string_view>(b);
                if (view.size() != out.size())
                {
                    throw py::value_error(std::string(what) + " must be " + std::to_string(out.size()) + " bytes");
                }
                std::memcpy(out.data(), view.data(), out.size());
            };
            xicap::TranscodeOptions options{};
            options.signing = seal ? xicap::Signing::Seal : xicap::Signing::Reissue;
            options.agent   = agent;
            take(seed, options.seed, "seed");
            if (!signer.is_none())
            {
                const auto          d = signer.cast<py::dict>();
                xicap::SourceSigner out{};
                take(d["key"].cast<py::bytes>(), out.key, "signer key");
                out.signedToEnd     = d["signedToEnd"].cast<bool>();
                out.verifiedPackets = d["verifiedPackets"].cast<uint64_t>();
                options.signer      = out;
            }
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
        },
        py::arg("src"),
        py::arg("dst"),
        py::kw_only(),
        py::arg("seal"),
        py::arg("seed"),
        py::arg("agent"),
        py::arg("level")  = 0,
        py::arg("signer") = py::none(),
        "Rewrites src at dst with the archive preset and checks it against src. seal=True keeps the signer's "
        "signatures and adds a seal made with seed; seal=False reissues a file its own signer's seed signs, with the "
        "source signer given as {key, signedToEnd, verifiedPackets}.");
}
