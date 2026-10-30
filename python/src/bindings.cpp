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

// Fresh Python bytes holding a copy of an extension's data.
auto extToBytes(const xicap::ExtensionBlock& ext) -> py::bytes
{
    return py::bytes(reinterpret_cast<const char*>(ext.data.data()), ext.data.size());
}

// Fresh Python bytes from a span. Used for ReadPacket.data because the source
// span lives in the Reader's frame buffer and is invalidated by the next call.
auto spanToBytes(std::span<const std::byte> s) -> py::bytes
{
    return py::bytes(reinterpret_cast<const char*>(s.data()), s.size());
}

// Plain Python object representing one packet. We don't bind ReadPacket
// directly — its data field is a span pointing into Reader-owned memory, so
// every iteration step must materialise a fresh Python object.
struct PyPacket
{
    uint64_t                 timestampMs;
    uint16_t                 opcode;
    xicap::PacketDirection   direction;
    py::bytes                data;
    std::vector<std::string> markers;
};

class PyReader
{
public:
    explicit PyReader(const std::filesystem::path& path)
    : reader_(std::make_unique<xicap::Reader>(path))
    {
    }

    [[nodiscard]] auto next() -> std::optional<PyPacket>
    {
        if (!reader_->next(pkt_))
        {
            return std::nullopt;
        }
        std::vector<std::string> markers;
        markers.reserve(pkt_.markers.size());
        for (const auto& m : pkt_.markers)
        {
            markers.push_back(m.text);
        }
        return PyPacket{
            .timestampMs = pkt_.timestamp,
            .opcode      = pkt_.opcode,
            .direction   = pkt_.direction,
            .data        = spanToBytes(pkt_.data),
            .markers     = std::move(markers),
        };
    }

    auto skipCurrentFrame() -> void
    {
        reader_->skipCurrentFrame();
    }
    auto reset() -> void
    {
        reader_->reset();
    }

    [[nodiscard]] auto seekToFrame(uint64_t i) -> xicap::SeekResult
    {
        return reader_->seekToFrame(i);
    }
    [[nodiscard]] auto seekToTime(uint64_t t) -> xicap::SeekResult
    {
        return reader_->seekToTime(t);
    }
    [[nodiscard]] auto seekToZone(uint16_t z) -> xicap::SeekResult
    {
        return reader_->seekToZone(z);
    }

    [[nodiscard]] auto versionMajor() const -> int
    {
        return reader_->versionMajor();
    }
    [[nodiscard]] auto versionMinor() const -> int
    {
        return reader_->versionMinor();
    }
    [[nodiscard]] auto clientVersion() const -> std::string
    {
        return reader_->clientVersion();
    }
    [[nodiscard]] auto captureAgent() const -> std::string
    {
        return reader_->captureAgent();
    }
    [[nodiscard]] auto startZoneId() const -> uint16_t
    {
        return reader_->startZoneId();
    }
    [[nodiscard]] auto endZoneId() const -> uint16_t
    {
        return reader_->endZoneId();
    }
    [[nodiscard]] auto startWeather() const -> uint8_t
    {
        return reader_->startWeather();
    }
    [[nodiscard]] auto startTimestampMs() const -> uint64_t
    {
        return reader_->startTimestamp();
    }
    [[nodiscard]] auto endTimestampMs() const -> uint64_t
    {
        return reader_->endTimestamp();
    }
    [[nodiscard]] auto durationMs() const -> uint64_t
    {
        return reader_->durationMs();
    }
    [[nodiscard]] auto totalFrames() const -> uint64_t
    {
        return reader_->totalFrames();
    }
    [[nodiscard]] auto totalPacketCount() const -> uint64_t
    {
        return reader_->totalPacketCount();
    }
    [[nodiscard]] auto hasFooter() const -> bool
    {
        return reader_->hasFooter();
    }

    [[nodiscard]] auto lobby() const -> py::object
    {
        const auto& l = reader_->lobby();
        py::dict    out;
        out["contentId"]         = l.contentId;
        out["worldContentId"]    = l.worldContentId;
        out["worldId"]           = l.worldId;
        out["status"]            = l.status;
        out["pendingRename"]     = static_cast<bool>(l.pendingRename);
        out["pendingRaceChange"] = static_cast<bool>(l.pendingRaceChange);
        out["worldTableIndex"]   = l.worldTableIndex;
        out["characterName"]     = std::string(l.characterName.data(),
                                               ::strnlen(l.characterName.data(), l.characterName.size()));
        out["worldName"]         = std::string(l.worldName.data(),
                                               ::strnlen(l.worldName.data(), l.worldName.size()));
        return out;
    }

    [[nodiscard]] auto extensionTypes() const -> std::vector<uint32_t>
    {
        std::vector<uint32_t> types;
        types.reserve(reader_->extensions().size());
        for (const auto& e : reader_->extensions())
        {
            types.push_back(e.type);
        }
        return types;
    }

    [[nodiscard]] auto getExtension(uint32_t type) const -> std::optional<py::bytes>
    {
        const auto* ext = reader_->getExtension(type);
        if (ext == nullptr)
        {
            return std::nullopt;
        }
        return extToBytes(*ext);
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
    xicap::ReadPacket              pkt_;
};

} // namespace

PYBIND11_MODULE(_xicap, m)
{
    m.doc() = "Native bindings for the xicap reader.";

    py::enum_<xicap::PacketDirection>(m, "PacketDirection")
        .value("ServerToClient", xicap::PacketDirection::ServerToClient)
        .value("ClientToServer", xicap::PacketDirection::ClientToServer);

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
        .value("CompressFailed", xicap::ErrorCode::CompressFailed);

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
        .def_readonly("opcode", &PyPacket::opcode)
        .def_readonly("direction", &PyPacket::direction)
        .def_readonly("data", &PyPacket::data)
        .def_readonly("markers", &PyPacket::markers);

    py::class_<PyReader>(m, "Reader")
        .def(py::init<const std::filesystem::path&>(), py::arg("path"))
        .def("next", &PyReader::next)
        .def("skip_current_frame", &PyReader::skipCurrentFrame)
        .def("reset", &PyReader::reset)
        .def("seek_to_frame", &PyReader::seekToFrame)
        .def("seek_to_time", &PyReader::seekToTime)
        .def("seek_to_zone", &PyReader::seekToZone)
        .def_property_readonly("version_major", &PyReader::versionMajor)
        .def_property_readonly("version_minor", &PyReader::versionMinor)
        .def_property_readonly("client_version", &PyReader::clientVersion)
        .def_property_readonly("capture_agent", &PyReader::captureAgent)
        .def_property_readonly("start_zone_id", &PyReader::startZoneId)
        .def_property_readonly("end_zone_id", &PyReader::endZoneId)
        .def_property_readonly("start_weather", &PyReader::startWeather)
        .def_property_readonly("start_timestamp_ms", &PyReader::startTimestampMs)
        .def_property_readonly("end_timestamp_ms", &PyReader::endTimestampMs)
        .def_property_readonly("duration_ms", &PyReader::durationMs)
        .def_property_readonly("total_frames", &PyReader::totalFrames)
        .def_property_readonly("total_packet_count", &PyReader::totalPacketCount)
        .def_property_readonly("has_footer", &PyReader::hasFooter)
        .def_property_readonly("lobby", &PyReader::lobby)
        .def("extension_types", &PyReader::extensionTypes)
        .def("get_extension", &PyReader::getExtension, py::arg("type"))
        .def("list_zones", &PyReader::listZones);
}
