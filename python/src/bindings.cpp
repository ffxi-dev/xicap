#include <xicap/reader.h>

#include <pybind11/pybind11.h>
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

// A packet with its own copy of the bytes, since the reader's copy lasts only until the next packet.
struct Packet
{
    uint64_t               timestamp{};
    uint16_t               flags{};
    uint8_t                channel{};
    uint16_t               opcode{};
    xicap::PacketDirection direction{};
    py::bytes              data;
};

} // namespace

PYBIND11_MODULE(xicap, m)
{
    m.doc() = "Reads xicap captures of Final Fantasy XI packets.";

    py::register_exception<xicap::Error>(m, "Error");

    py::enum_<xicap::Network>(m, "Network")
        .value("Unknown", xicap::Network::Unknown)
        .value("Retail", xicap::Network::Retail)
        .value("Private", xicap::Network::Private);
    py::enum_<xicap::PacketDirection>(m, "Direction")
        .value("ServerToClient", xicap::PacketDirection::ServerToClient)
        .value("ClientToServer", xicap::PacketDirection::ClientToServer);

    py::class_<xicap::Character>(m, "Character")
        .def_readonly("character_id", &xicap::Character::characterId)
        .def_property_readonly("name", [](const xicap::Character& c)
                               {
                                   return str(c.name);
                               });

    py::class_<Packet>(m, "Packet")
        .def_readonly("timestamp", &Packet::timestamp)
        .def_readonly("flags", &Packet::flags)
        .def_readonly("channel", &Packet::channel)
        .def_readonly("opcode", &Packet::opcode)
        .def_readonly("direction", &Packet::direction)
        .def_readonly("data", &Packet::data);

    py::class_<xicap::Reader>(m, "Reader")
        .def(py::init<std::filesystem::path>(), py::arg("path"))
        .def_property_readonly("start_timestamp", [](const xicap::Reader& r)
                               {
                                   return r.metadata().startTimestamp;
                               })
        .def_property_readonly("network", [](const xicap::Reader& r)
                               {
                                   return r.metadata().network;
                               })
        .def_property_readonly("client_version", [](const xicap::Reader& r)
                               {
                                   return str(r.metadata().clientVersion);
                               })
        .def_property_readonly("character", [](const xicap::Reader& r)
                               {
                                   return r.metadata().character;
                               })
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
                 };
             });
}
