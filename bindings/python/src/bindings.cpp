#include <xicap/reader.h>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl/filesystem.h>

#include <string>
#include <vector>

namespace py = pybind11;

namespace
{

// FORMAT.md lets a reader replace bytes that are not UTF-8 with U+FFFD, where pybind11 would raise.
template <typename T>
auto text(std::string T::* field) -> py::cpp_function
{
    return [field](const T& o)
    {
        const auto& s = o.*field;
        return py::reinterpret_steal<py::str>(PyUnicode_DecodeUTF8(s.data(), static_cast<Py_ssize_t>(s.size()), "replace"));
    };
}

template <typename T, typename Bytes>
auto bytes(Bytes T::* field) -> py::cpp_function
{
    return [field](const T& o)
    {
        const auto& b = o.*field;
        return py::bytes(reinterpret_cast<const char*>(b.data()), b.size());
    };
}

// The reader's packet lasts only until its next one, so Python gets a copy.
struct Packet
{
    uint64_t                   timestamp{};
    uint16_t                   flags{};
    uint8_t                    channel{};
    uint16_t                   opcode{};
    xicap::PacketDirection     direction{};
    py::bytes                  data;
    std::vector<xicap::Marker> markers;
};

} // namespace

PYBIND11_MODULE(xicap, m)
{
    m.doc() = "Reads xicap captures of Final Fantasy XI packets.";

    py::register_exception<xicap::Error>(m, "Error");

    py::enum_<xicap::Origin>(m, "Origin")
        .value("Unknown", xicap::Origin::Unknown)
        .value("Live", xicap::Origin::Live)
        .value("Converted", xicap::Origin::Converted);
    py::enum_<xicap::ServerKind>(m, "ServerKind")
        .value("Unknown", xicap::ServerKind::Unknown)
        .value("Retail", xicap::ServerKind::Retail)
        .value("Private", xicap::ServerKind::Private);
    py::enum_<xicap::MarkerKind>(m, "MarkerKind")
        .value("Note", xicap::MarkerKind::Note)
        .value("Login", xicap::MarkerKind::Login)
        .value("Logout", xicap::MarkerKind::Logout);
    py::enum_<xicap::PacketDirection>(m, "Direction")
        .value("ServerToClient", xicap::PacketDirection::ServerToClient)
        .value("ClientToServer", xicap::PacketDirection::ClientToServer);

    py::class_<xicap::Character>(m, "Character")
        .def_readonly("content_id", &xicap::Character::contentId)
        .def_readonly("character_id", &xicap::Character::characterId)
        .def_property_readonly("name", text(&xicap::Character::name))
        .def_property_readonly("world", text(&xicap::Character::world));

    py::class_<xicap::Source>(m, "Source")
        .def_property_readonly("format", text(&xicap::Source::format))
        .def_property_readonly("format_version", text(&xicap::Source::formatVersion))
        .def_readonly("skipped_records", &xicap::Source::skippedRecords)
        .def_property_readonly("metadata", bytes(&xicap::Source::metadata));

    py::class_<xicap::Metadata>(m, "Metadata")
        .def_property_readonly("capture_id", bytes(&xicap::Metadata::captureId))
        .def_property_readonly("previous_capture_id", bytes(&xicap::Metadata::previousCaptureId))
        .def_readonly("start_timestamp", &xicap::Metadata::startTimestamp)
        .def_readonly("origin", &xicap::Metadata::origin)
        .def_readonly("server_kind", &xicap::Metadata::serverKind)
        .def_property_readonly("capture_agent", text(&xicap::Metadata::captureAgent))
        .def_property_readonly("client_version", text(&xicap::Metadata::clientVersion))
        .def_readonly("character", &xicap::Metadata::character)
        .def_readonly("source", &xicap::Metadata::source);

    py::class_<xicap::Marker>(m, "Marker")
        .def_readonly("kind", &xicap::Marker::kind)
        .def_property_readonly("text", text(&xicap::Marker::text));

    py::class_<Packet>(m, "Packet")
        .def_readonly("timestamp", &Packet::timestamp)
        .def_readonly("flags", &Packet::flags)
        .def_readonly("channel", &Packet::channel)
        .def_readonly("opcode", &Packet::opcode)
        .def_readonly("direction", &Packet::direction)
        .def_readonly("data", &Packet::data)
        .def_readonly("markers", &Packet::markers);

    py::class_<xicap::Reader>(m, "Reader")
        .def(py::init<std::filesystem::path>(), py::arg("path"))
        .def_property_readonly("metadata", &xicap::Reader::metadata)
        .def_property_readonly("complete", &xicap::Reader::complete)
        .def_property_readonly("end_timestamp", &xicap::Reader::endTimestamp)
        .def_property_readonly("packet_count", &xicap::Reader::packetCount)
        .def("__iter__", [](py::object self)
             {
                 return self;
             })
        .def("__next__", [](xicap::Reader& r)
             {
                 xicap::Packet p;
                 if (!r.next(p))
                 {
                     throw py::stop_iteration();
                 }

                 return Packet{
                     .timestamp = p.timestamp,
                     .flags     = p.flags,
                     .channel   = p.channel,
                     .opcode    = p.opcode,
                     .direction = p.direction(),
                     .data      = { reinterpret_cast<const char*>(p.data.data()), p.data.size() },
                     .markers   = { p.markers.begin(), p.markers.end() },
                 };
             });
}
