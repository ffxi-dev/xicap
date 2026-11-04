#include <xicap/reader.h>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/stl/filesystem.h>

#include <filesystem>
#include <string_view>

namespace py = pybind11;

namespace
{

// Text is UTF-8 as stored; a byte that does not start a character reads as U+FFFD rather than failing.
auto str(std::string_view text) -> py::str
{
    return py::reinterpret_steal<py::str>(PyUnicode_DecodeUTF8(text.data(), static_cast<Py_ssize_t>(text.size()), "replace"));
}

template <typename Bytes>
auto bytes(const Bytes& b) -> py::bytes
{
    return { reinterpret_cast<const char*>(b.data()), b.size() };
}

auto packet(const xicap::Packet& p) -> py::object
{
    py::list markers;
    for (const auto& m : p.markers)
    {
        markers.append(py::make_tuple(m.kind, str(m.text)));
    }
    static const auto make = py::module_::import("types").attr("SimpleNamespace");
    return make(py::arg("timestamp") = p.timestamp, py::arg("flags") = p.flags, py::arg("channel") = p.channel, py::arg("opcode") = p.opcode, py::arg("direction") = p.direction(), py::arg("data") = bytes(p.data), py::arg("markers") = markers);
}

} // namespace

PYBIND11_MODULE(xicap, m)
{
    m.doc() = "Reads xicap captures of Final Fantasy XI packets.";

    py::register_exception<xicap::Error>(m, "Error");

    py::enum_<xicap::Origin>(m, "Origin")
        .value("Unknown", xicap::Origin::Unknown)
        .value("Live", xicap::Origin::Live)
        .value("Converted", xicap::Origin::Converted);
    py::enum_<xicap::Network>(m, "Network")
        .value("Unknown", xicap::Network::Unknown)
        .value("Retail", xicap::Network::Retail)
        .value("Private", xicap::Network::Private);
    py::enum_<xicap::PacketDirection>(m, "Direction")
        .value("ServerToClient", xicap::PacketDirection::ServerToClient)
        .value("ClientToServer", xicap::PacketDirection::ClientToServer);
    py::enum_<xicap::MarkerKind>(m, "MarkerKind")
        .value("Note", xicap::MarkerKind::Note)
        .value("Login", xicap::MarkerKind::Login)
        .value("Logout", xicap::MarkerKind::Logout);

    py::class_<xicap::Character>(m, "Character")
        .def_readonly("content_id", &xicap::Character::contentId)
        .def_readonly("character_id", &xicap::Character::characterId)
        .def_property_readonly("name", [](const xicap::Character& c)
                               {
                                   return str(c.name);
                               })
        .def_property_readonly("world", [](const xicap::Character& c)
                               {
                                   return str(c.world);
                               });

    py::class_<xicap::Source>(m, "Source")
        .def_property_readonly("format", [](const xicap::Source& s)
                               {
                                   return str(s.format);
                               })
        .def_property_readonly("format_version", [](const xicap::Source& s)
                               {
                                   return str(s.formatVersion);
                               })
        .def_readonly("skipped_records", &xicap::Source::skippedRecords)
        .def_property_readonly("metadata", [](const xicap::Source& s)
                               {
                                   return bytes(s.metadata);
                               });

    py::class_<xicap::Reader>(m, "Reader")
        .def(py::init<std::filesystem::path>(), py::arg("path"))
        .def_property_readonly("capture_id", [](const xicap::Reader& r)
                               {
                                   return bytes(r.metadata().captureId);
                               })
        .def_property_readonly("previous_capture_id", [](const xicap::Reader& r)
                               {
                                   return bytes(r.metadata().previousCaptureId);
                               })
        .def_property_readonly("start_timestamp", [](const xicap::Reader& r)
                               {
                                   return r.metadata().startTimestamp;
                               })
        .def_property_readonly("origin", [](const xicap::Reader& r)
                               {
                                   return r.metadata().origin;
                               })
        .def_property_readonly("network", [](const xicap::Reader& r)
                               {
                                   return r.metadata().network;
                               })
        .def_property_readonly("capture_agent", [](const xicap::Reader& r)
                               {
                                   return str(r.metadata().captureAgent);
                               })
        .def_property_readonly("client_version", [](const xicap::Reader& r)
                               {
                                   return str(r.metadata().clientVersion);
                               })
        .def_property_readonly("character", [](const xicap::Reader& r)
                               {
                                   return r.metadata().character;
                               })
        .def_property_readonly("policy_name", [](const xicap::Reader& r)
                               {
                                   return str(r.metadata().policy.name);
                               })
        .def_property_readonly("policy_version", [](const xicap::Reader& r)
                               {
                                   return r.metadata().policy.version;
                               })
        .def_property_readonly("policy_rules", [](const xicap::Reader& r)
                               {
                                   return r.metadata().policy.rules.size();
                               })
        .def_property_readonly("source", [](const xicap::Reader& r)
                               {
                                   return r.metadata().source;
                               })
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
                 return packet(p);
             });
}
