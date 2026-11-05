#include <xicap/reader.h>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl/filesystem.h>

#include <string>
#include <vector>

namespace py = pybind11;

namespace
{

// Replace malformed UTF-8 with U+FFFD.
template <typename T>
auto text(std::string T::* const field) -> py::cpp_function
{
    return [field](const T& o)
    {
        const auto& s = o.*field;
        return py::reinterpret_steal<py::str>(PyUnicode_DecodeUTF8(s.data(), static_cast<Py_ssize_t>(s.size()), "replace"));
    };
}

template <typename T, typename Bytes>
auto bytes(Bytes T::* const field) -> py::cpp_function
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
    py::bytes                  data;
    std::vector<xicap::Marker> markers;
};

} // namespace

PYBIND11_MODULE(xicap, m)
{
    m.doc() = "Reads xicap captures of Final Fantasy XI packets.";

    py::register_exception<xicap::Error>(m, "Error");

    // Python enums over plain ints, so a value compares with what the API returns and an unknown one stays an int.
    const auto python    = py::module_::import("enum");
    m.attr("Origin")     = python.attr("IntEnum")("Origin", py::dict(py::arg("Unknown") = 0, py::arg("Live") = 1, py::arg("Converted") = 2));
    m.attr("ServerKind") = python.attr("IntEnum")("ServerKind", py::dict(py::arg("Unknown") = 0, py::arg("Retail") = 1, py::arg("Private") = 2));
    m.attr("MarkerKind") = python.attr("IntEnum")("MarkerKind", py::dict(py::arg("Note") = 0, py::arg("Login") = 1, py::arg("Logout") = 2));
    m.attr("Channel")    = python.attr("IntEnum")("Channel", py::dict(py::arg("Game") = 0, py::arg("Search") = 1));
    m.attr("PacketFlag") = python.attr("IntFlag")("PacketFlag", py::dict(py::arg("ClientToServer") = xicap::PacketFlag::ClientToServer, py::arg("Injected") = xicap::PacketFlag::Injected, py::arg("Blocked") = xicap::PacketFlag::Blocked, py::arg("Modified") = xicap::PacketFlag::Modified, py::arg("FirstInDatagram") = xicap::PacketFlag::FirstInDatagram, py::arg("Excluded") = xicap::PacketFlag::Excluded, py::arg("Redacted") = xicap::PacketFlag::Redacted));

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
        .def_property_readonly("origin", [](const xicap::Metadata& o)
                               {
                                   return static_cast<int>(o.origin);
                               })
        .def_property_readonly("server_kind", [](const xicap::Metadata& o)
                               {
                                   return static_cast<int>(o.serverKind);
                               })
        .def_property_readonly("capture_agent", text(&xicap::Metadata::captureAgent))
        .def_property_readonly("client_version", text(&xicap::Metadata::clientVersion))
        .def_readonly("character", &xicap::Metadata::character)
        .def_readonly("source", &xicap::Metadata::source);

    py::class_<xicap::Marker>(m, "Marker")
        .def_property_readonly("kind", [](const xicap::Marker& o)
                               {
                                   return static_cast<int>(o.kind);
                               })
        .def_property_readonly("text", text(&xicap::Marker::text));

    py::class_<Packet>(m, "Packet")
        .def_readonly("timestamp", &Packet::timestamp)
        .def_readonly("flags", &Packet::flags)
        .def_readonly("channel", &Packet::channel)
        .def_readonly("opcode", &Packet::opcode)
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
                     .data      = { reinterpret_cast<const char*>(p.data.data()), p.data.size() },
                     .markers   = { p.markers.begin(), p.markers.end() },
                 };
             });
}
