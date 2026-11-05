#include <xicap/reader.h>

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace em = emscripten;

namespace
{

template <typename F>
auto guard(F&& f) -> decltype(f())
{
    try
    {
        return f();
    }
    catch (const std::exception& e)
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

// A JS string cannot hold bytes that are not UTF-8, so TextDecoder replaces them with U+FFFD, as FORMAT.md allows.
auto text(std::string_view s) -> em::val
{
    static const auto decoder = em::val::global("TextDecoder").new_();
    return decoder.call<em::val>("decode", em::val(em::typed_memory_view(s.size(), reinterpret_cast<const uint8_t*>(s.data()))));
}

auto metadata(const xicap::Metadata& m) -> em::val
{
    auto character = em::val::object();
    character.set("contentId", m.character.contentId);
    character.set("characterId", m.character.characterId);
    character.set("name", text(m.character.name));
    character.set("world", text(m.character.world));
    auto policy = em::val::object();
    policy.set("name", text(m.policy.name));
    policy.set("version", m.policy.version);
    policy.set("rules", m.policy.rules.size());
    auto source = em::val::null();
    if (m.source)
    {
        source = em::val::object();
        source.set("format", text(m.source->format));
        source.set("formatVersion", text(m.source->formatVersion));
        source.set("skippedRecords", m.source->skippedRecords);
        source.set("metadata", bytes(m.source->metadata));
    }

    auto o = em::val::object();
    o.set("captureId", bytes(m.captureId));
    o.set("previousCaptureId", bytes(m.previousCaptureId));
    o.set("startTimestamp", static_cast<double>(m.startTimestamp));
    o.set("origin", static_cast<int>(m.origin));
    o.set("serverKind", static_cast<int>(m.serverKind));
    o.set("captureAgent", text(m.captureAgent));
    o.set("clientVersion", text(m.clientVersion));
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
        marker.set("text", text(m.text));
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
    auto push(const em::val& chunk) -> em::val
    {
        return guard([&]
                     {
                         const auto data = em::convertJSArrayToNumberVector<uint8_t>(chunk);
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
