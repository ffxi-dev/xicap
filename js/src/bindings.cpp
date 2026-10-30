#include <xicap/xicap.h>

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace em = emscripten;

namespace
{

// Embind catches every C++ throw and surfaces it to JS as a generic
// CppException. To preserve the typed ErrorCode + message we stash both into a
// process-global side channel before letting the exception propagate; the TS
// wrapper drains the side channel after catching and synthesises a typed
// XicapError instance.
struct LastError
{
    int         code = -1;
    std::string message;
    bool        present = false;
};
inline auto lastError() -> LastError&
{
    static LastError e;
    return e;
}

template <typename F>
auto withJsErrors(F&& f) -> decltype(f())
{
    try
    {
        return std::forward<F>(f)();
    }
    catch (const xicap::Error& e)
    {
        lastError() = LastError{ static_cast<int>(e.code()), e.what(), true };
        throw;
    }
}

// A JS-owned copy: views into the wasm heap go stale on the next call.
auto copyBytes(const void* data, size_t size) -> em::val
{
    em::val u8 = em::val::global("Uint8Array").new_(size);
    u8.call<void>("set", em::val(em::typed_memory_view(size, static_cast<const uint8_t*>(data))));
    return u8;
}

template <typename T>
auto copyBytes(const T& bytes) -> em::val
{
    return copyBytes(bytes.data(), bytes.size());
}

template <size_t N>
auto text(const std::array<char, N>& field) -> std::string
{
    return { field.data(), ::strnlen(field.data(), N) };
}

// Wraps xicap::Reader for Embind. Lifecycle: Reader.open writes the input bytes
// to a MEMFS path and constructs the C++ Reader against that path. delete()
// releases the C++ object; the JS wrapper removes the MEMFS file.
class JsReader
{
public:
    JsReader(std::string memPath, bool recovery)
    : path_(std::move(memPath))
    {
        withJsErrors([&]() -> int
                     {
                         reader_ = std::make_unique<xicap::Reader>(path_, xicap::ReaderOptions{ .recovery = recovery });
                         return 0;
                     });
    }

    [[nodiscard]] auto versionMajor() const -> uint8_t
    {
        return reader_->versionMajor();
    }
    [[nodiscard]] auto versionMinor() const -> uint8_t
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
    [[nodiscard]] auto captureId() const -> em::val
    {
        return copyBytes(reader_->captureId());
    }
    [[nodiscard]] auto previousCaptureId() const -> em::val
    {
        return copyBytes(reader_->previousCaptureId());
    }
    [[nodiscard]] auto signingKey() const -> em::val
    {
        return copyBytes(reader_->signingKey());
    }
    [[nodiscard]] auto clockSource() const -> int
    {
        return static_cast<int>(reader_->clockSource());
    }
    [[nodiscard]] auto origin() const -> int
    {
        return static_cast<int>(reader_->origin());
    }
    [[nodiscard]] auto network() const -> int
    {
        return static_cast<int>(reader_->network());
    }
    [[nodiscard]] auto startContext() const -> int
    {
        return static_cast<int>(reader_->startContext());
    }
    // JS numbers are doubles, safe up to 2^53. Unix-ms timestamps fit.
    [[nodiscard]] auto startTimestampMs() const -> double
    {
        return static_cast<double>(reader_->startTimestamp());
    }
    [[nodiscard]] auto endTimestampMs() const -> double
    {
        return static_cast<double>(reader_->endTimestamp());
    }
    [[nodiscard]] auto durationMs() const -> double
    {
        return static_cast<double>(reader_->durationMs());
    }
    [[nodiscard]] auto totalFrames() const -> double
    {
        return static_cast<double>(reader_->totalFrames());
    }
    [[nodiscard]] auto totalPacketCount() const -> double
    {
        return static_cast<double>(reader_->totalPacketCount());
    }
    [[nodiscard]] auto complete() const -> bool
    {
        return reader_->complete();
    }
    [[nodiscard]] auto footerDamaged() const -> bool
    {
        return reader_->footerDamaged();
    }
    [[nodiscard]] auto characterMismatch() const -> bool
    {
        return reader_->characterMismatch();
    }
    [[nodiscard]] auto unreadBytes() const -> double
    {
        return static_cast<double>(reader_->unreadBytes());
    }

    [[nodiscard]] auto character() const -> em::val
    {
        const auto& c = reader_->character();
        em::val     o = em::val::object();
        o.set("contentId", static_cast<double>(c.contentId));
        o.set("characterId", static_cast<double>(c.characterId));
        o.set("worldId", c.worldId);
        o.set("characterName", text(c.characterName));
        o.set("worldName", text(c.worldName));
        return o;
    }

    [[nodiscard]] auto policy() const -> em::val
    {
        const auto& p     = reader_->policy();
        em::val     rules = em::val::array();
        for (size_t i = 0; i < p.rules.size(); ++i)
        {
            const auto& r      = p.rules[i];
            em::val     ranges = em::val::array();
            for (size_t j = 0; j < r.ranges.size(); ++j)
            {
                em::val range = em::val::object();
                range.set("offset", static_cast<double>(r.ranges[j].offset));
                range.set("length", static_cast<double>(r.ranges[j].length));
                ranges.set(j, range);
            }
            em::val rule = em::val::object();
            rule.set("channel", r.channel);
            rule.set("direction", static_cast<int>(r.direction));
            rule.set("action", static_cast<int>(r.action));
            rule.set("opcode", r.opcode);
            rule.set("ranges", ranges);
            rules.set(i, rule);
        }
        em::val o = em::val::object();
        o.set("name", p.name);
        o.set("version", static_cast<double>(p.version));
        o.set("rules", rules);
        return o;
    }

    [[nodiscard]] auto source() const -> em::val
    {
        const auto& s = reader_->source();
        if (!s)
        {
            return em::val::null();
        }
        em::val o = em::val::object();
        o.set("format", s->format);
        o.set("formatVersion", s->formatVersion);
        o.set("skippedRecords", static_cast<double>(s->skippedRecords));
        o.set("utcOffsetSeconds", s->utcOffsetSeconds);
        o.set("sourceHash", copyBytes(s->sourceHash));
        o.set("metadata", copyBytes(s->metadata));
        return o;
    }

    auto verify() -> em::val
    {
        return withJsErrors([&]() -> em::val
                            {
                                const auto v = reader_->verify();
                                em::val    o = em::val::object();
                                o.set("key", copyBytes(v.key));
                                o.set("signedToEnd", v.signedToEnd);
                                o.set("verifiedPackets", static_cast<double>(v.verifiedPackets));
                                o.set("goodCheckpoints", static_cast<double>(v.goodCheckpoints));
                                o.set("firstFailureOffset", v.firstFailureOffset ? em::val(static_cast<double>(*v.firstFailureOffset)) : em::val::null());
                                return o;
                            });
    }

    [[nodiscard]] auto skippedRegions() const -> em::val
    {
        em::val arr = em::val::array();
        size_t  i   = 0;
        for (const auto& r : reader_->skippedRegions())
        {
            em::val o = em::val::object();
            o.set("offset", static_cast<double>(r.offset));
            o.set("length", static_cast<double>(r.length));
            arr.set(i++, o);
        }
        return arr;
    }

    [[nodiscard]] auto extensionTypes() const -> em::val
    {
        em::val arr = em::val::array();
        for (size_t i = 0; i < reader_->extensions().size(); ++i)
        {
            arr.set(i, static_cast<double>(reader_->extensions()[i].type));
        }
        return arr;
    }

    // A Uint8Array copy of the extension's data, or null if not present.
    [[nodiscard]] auto getExtension(uint32_t type) const -> em::val
    {
        const auto* ext = reader_->getExtension(type);
        return ext ? copyBytes(ext->data) : em::val::null();
    }

    [[nodiscard]] auto listZones() const -> em::val
    {
        em::val arr = em::val::array();
        size_t  i   = 0;
        for (const auto& z : reader_->listZones())
        {
            em::val o = em::val::object();
            o.set("zoneId", z.zoneId);
            o.set("timestampMs", static_cast<double>(z.timestamp));
            o.set("fileOffset", static_cast<double>(z.fileOffset));
            arr.set(i++, o);
        }
        return arr;
    }

    // The next packet as a JS object, or null at the end of the capture.
    auto next() -> em::val
    {
        return withJsErrors([&]() -> em::val
                            {
                                if (!reader_->next(pkt_))
                                {
                                    return em::val::null();
                                }
                                em::val o = em::val::object();
                                o.set("timestampMs", static_cast<double>(pkt_.timestamp));
                                o.set("channel", pkt_.channel);
                                o.set("opcode", pkt_.opcode);
                                o.set("flags", pkt_.flags);
                                o.set("direction", static_cast<int>(pkt_.direction));
                                o.set("data", copyBytes(pkt_.data.data(), pkt_.data.size()));

                                em::val markers = em::val::array();
                                size_t  mi      = 0;
                                for (const auto& m : pkt_.markers)
                                {
                                    em::val marker = em::val::object();
                                    marker.set("kind", static_cast<int>(m.kind));
                                    marker.set("text", m.text);
                                    markers.set(mi++, marker);
                                }
                                o.set("markers", markers);
                                return o;
                            });
    }

    auto skipCurrentFrame() -> void
    {
        reader_->skipCurrentFrame();
    }
    auto seekToFrame(double frameIndex) -> int
    {
        return withJsErrors([&]
                            {
                                return static_cast<int>(reader_->seekToFrame(static_cast<uint64_t>(frameIndex)));
                            });
    }
    auto seekToTime(double timestampMs) -> int
    {
        return withJsErrors([&]
                            {
                                return static_cast<int>(reader_->seekToTime(static_cast<uint64_t>(timestampMs)));
                            });
    }
    auto seekToZone(uint16_t zoneId) -> int
    {
        return withJsErrors([&]
                            {
                                return static_cast<int>(reader_->seekToZone(zoneId));
                            });
    }

private:
    std::string                    path_;
    std::unique_ptr<xicap::Reader> reader_;
    xicap::ReadPacket              pkt_{};
};

} // namespace

EMSCRIPTEN_BINDINGS(xicap_module)
{
    em::class_<JsReader>("Reader")
        .constructor<std::string, bool>()
        .function("versionMajor", &JsReader::versionMajor)
        .function("versionMinor", &JsReader::versionMinor)
        .function("clientVersion", &JsReader::clientVersion)
        .function("captureAgent", &JsReader::captureAgent)
        .function("captureId", &JsReader::captureId)
        .function("previousCaptureId", &JsReader::previousCaptureId)
        .function("signingKey", &JsReader::signingKey)
        .function("clockSource", &JsReader::clockSource)
        .function("origin", &JsReader::origin)
        .function("network", &JsReader::network)
        .function("startContext", &JsReader::startContext)
        .function("startTimestampMs", &JsReader::startTimestampMs)
        .function("endTimestampMs", &JsReader::endTimestampMs)
        .function("durationMs", &JsReader::durationMs)
        .function("totalFrames", &JsReader::totalFrames)
        .function("totalPacketCount", &JsReader::totalPacketCount)
        .function("complete", &JsReader::complete)
        .function("footerDamaged", &JsReader::footerDamaged)
        .function("characterMismatch", &JsReader::characterMismatch)
        .function("unreadBytes", &JsReader::unreadBytes)
        .function("character", &JsReader::character)
        .function("policy", &JsReader::policy)
        .function("source", &JsReader::source)
        .function("verify", &JsReader::verify)
        .function("skippedRegions", &JsReader::skippedRegions)
        .function("extensionTypes", &JsReader::extensionTypes)
        .function("getExtension", &JsReader::getExtension)
        .function("listZones", &JsReader::listZones)
        .function("next", &JsReader::next)
        .function("skipCurrentFrame", &JsReader::skipCurrentFrame)
        .function("seekToFrame", &JsReader::seekToFrame)
        .function("seekToTime", &JsReader::seekToTime)
        .function("seekToZone", &JsReader::seekToZone);

    em::function("__takeLastError", +[]() -> em::val
                 {
                     auto& le = lastError();
                     if (!le.present)
                         return em::val::null();
                     em::val o = em::val::object();
                     o.set("code", le.code);
                     o.set("message", le.message);
                     le = LastError{};
                     return o;
                 });
}
