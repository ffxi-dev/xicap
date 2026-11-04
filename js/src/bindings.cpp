#include <xicap/reader.h>

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <memory>
#include <span>
#include <string>
#include <vector>

namespace em = emscripten;

namespace
{

// Runs f, turning an xicap::Error into a JS Error with its message.
template <typename F>
auto guard(F&& f) -> decltype(f())
{
    try
    {
        return f();
    }
    catch (const xicap::Error& e)
    {
        em::val::global("Error").new_(std::string(e.what())).throw_();
    }
}

// A copy the JS side owns: views into the wasm heap go stale.
template <typename Bytes>
auto bytes(const Bytes& b) -> em::val
{
    return em::val(em::typed_memory_view(b.size(), reinterpret_cast<const uint8_t*>(b.data()))).call<em::val>("slice");
}

auto metadata(const xicap::Metadata& m) -> em::val
{
    auto character = em::val::object();
    character.set("contentId", m.character.contentId);
    character.set("characterId", m.character.characterId);
    character.set("name", m.character.name);
    character.set("world", m.character.world);
    auto policy = em::val::object();
    policy.set("name", m.policy.name);
    policy.set("version", m.policy.version);
    policy.set("rules", m.policy.rules.size());
    auto source = em::val::null();
    if (m.source)
    {
        source = em::val::object();
        source.set("format", m.source->format);
        source.set("formatVersion", m.source->formatVersion);
        source.set("skippedRecords", m.source->skippedRecords);
        source.set("metadata", bytes(m.source->metadata));
    }

    auto o = em::val::object();
    o.set("captureId", bytes(m.captureId));
    o.set("previousCaptureId", bytes(m.previousCaptureId));
    o.set("startTimestamp", static_cast<double>(m.startTimestamp));
    o.set("origin", static_cast<int>(m.origin));
    o.set("network", static_cast<int>(m.network));
    o.set("captureAgent", m.captureAgent);
    o.set("clientVersion", m.clientVersion);
    o.set("character", character);
    o.set("policy", policy);
    o.set("source", source);
    return o;
}

auto packet(const xicap::Packet& p) -> em::val
{
    auto markers = em::val::array();
    for (const auto& m : p.markers)
    {
        auto marker = em::val::object();
        marker.set("kind", static_cast<int>(m.kind));
        marker.set("text", m.text);
        markers.call<void>("push", marker);
    }

    auto o = em::val::object();
    o.set("timestamp", static_cast<double>(p.timestamp));
    o.set("flags", p.flags);
    o.set("channel", p.channel);
    o.set("opcode", p.opcode);
    o.set("data", bytes(p.data));
    o.set("markers", markers);
    return o;
}

class Reader
{
public:
    explicit Reader(const std::string& path)
    : reader_(guard([&]
                    {
                        return std::make_unique<xicap::Reader>(path);
                    }))
    {
    }

    auto metadata() const -> em::val
    {
        return ::metadata(reader_->metadata());
    }

    auto complete() const -> bool
    {
        return reader_->complete();
    }

    auto endTimestamp() const -> double
    {
        return static_cast<double>(reader_->endTimestamp());
    }

    auto packetCount() const -> double
    {
        return static_cast<double>(reader_->packetCount());
    }

    // The next packet, or undefined at the end.
    auto next() -> em::val
    {
        return guard([&]
                     {
                         xicap::Packet p;
                         if (!reader_->next(p))
                         {
                             return em::val::undefined();
                         }

                         return packet(p);
                     });
    }

private:
    std::unique_ptr<xicap::Reader> reader_;
};

class StreamReader
{
public:
    // The packets whose frames these bytes completed.
    auto push(const em::val& chunk) -> em::val
    {
        return guard([&]
                     {
                         std::vector<uint8_t> data(chunk["length"].as<size_t>());
                         em::val(em::typed_memory_view(data.size(), data.data())).call<void>("set", chunk);
                         reader_.push(std::as_bytes(std::span{ data }));
                         auto          out = em::val::array();
                         xicap::Packet p;
                         while (reader_.next(p))
                         {
                             out.call<void>("push", packet(p));
                         }

                         return out;
                     });
    }

    auto metadata() const -> em::val
    {
        return ::metadata(reader_.metadata());
    }

    auto ready() const -> bool
    {
        return reader_.ready();
    }

    auto complete() const -> bool
    {
        return reader_.complete();
    }

    auto stopped() const -> bool
    {
        return reader_.stopped();
    }

private:
    xicap::StreamReader reader_;
};

} // namespace

EMSCRIPTEN_BINDINGS(xicap)
{
    em::class_<Reader>("Reader")
        .constructor<std::string>()
        .function("metadata", &Reader::metadata)
        .function("complete", &Reader::complete)
        .function("endTimestamp", &Reader::endTimestamp)
        .function("packetCount", &Reader::packetCount)
        .function("next", &Reader::next);
    em::class_<StreamReader>("StreamReader")
        .constructor<>()
        .function("push", &StreamReader::push)
        .function("metadata", &StreamReader::metadata)
        .function("ready", &StreamReader::ready)
        .function("complete", &StreamReader::complete)
        .function("stopped", &StreamReader::stopped);
}
