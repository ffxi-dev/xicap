#include <xicap/xicap.h>

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include <cstdint>
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

// Wraps xicap::Reader for Embind. Lifecycle: Reader.open writes the input bytes
// to a MEMFS path and constructs the C++ Reader against that path. delete()
// releases the C++ object and removes the MEMFS file.
class JsReader
{
public:
    explicit JsReader(std::string memPath)
    : path_(std::move(memPath))
    {
        withJsErrors([&]() -> int
                     {
                         reader_ = std::make_unique<xicap::Reader>(path_);
                         return 0;
                     });
    }

    ~JsReader()
    {
        reader_.reset();
        // MEMFS cleanup is handled in the JS wrapper (FS.unlink).
    }

    // Header accessors -------------------------------------------------------
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
    // JS numbers are doubles — safe up to 2^53. Unix-ms timestamps fit.
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
    [[nodiscard]] auto hasFooter() const -> bool
    {
        return reader_->hasFooter();
    }

    [[nodiscard]] auto lobby() const -> em::val
    {
        const auto& l = reader_->lobby();
        em::val     o = em::val::object();
        o.set("contentId", static_cast<double>(l.contentId));
        o.set("worldContentId", l.worldContentId);
        o.set("worldId", l.worldId);
        o.set("status", l.status);
        o.set("pendingRename", static_cast<bool>(l.pendingRename));
        o.set("pendingRaceChange", static_cast<bool>(l.pendingRaceChange));
        o.set("worldTableIndex", l.worldTableIndex);
        o.set("characterName", std::string(l.characterName.data(), ::strnlen(l.characterName.data(), l.characterName.size())));
        o.set("worldName", std::string(l.worldName.data(), ::strnlen(l.worldName.data(), l.worldName.size())));
        return o;
    }

    [[nodiscard]] auto extensionTypes() const -> em::val
    {
        em::val arr = em::val::array();
        for (size_t i = 0; i < reader_->extensions().size(); ++i)
        {
            arr.set(i, reader_->extensions()[i].type);
        }
        return arr;
    }

    // Returns Uint8Array of the extension data, or null if not present.
    [[nodiscard]] auto getExtension(uint32_t type) const -> em::val
    {
        const auto* ext = reader_->getExtension(type);
        if (ext == nullptr)
        {
            return em::val::null();
        }
        return em::val(em::typed_memory_view(ext->data.size(), ext->data.data()));
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

    // Iteration --------------------------------------------------------------

    // Returns the next packet as a JS object, or null at end-of-stream.
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
                                o.set("opcode", pkt_.opcode);
                                o.set("direction", static_cast<int>(pkt_.direction));

                                // Copy packet bytes into a JS-owned Uint8Array; the underlying span is
                                // invalidated by the next call.
                                const auto* bytes = reinterpret_cast<const uint8_t*>(pkt_.data.data());
                                em::val     u8    = em::val::global("Uint8Array").new_(pkt_.data.size());
                                u8.call<void>("set", em::val(em::typed_memory_view(pkt_.data.size(), bytes)));
                                o.set("data", u8);

                                em::val markers = em::val::array();
                                size_t  mi      = 0;
                                for (const auto& m : pkt_.markers)
                                {
                                    markers.set(mi++, m.text);
                                }
                                o.set("markers", markers);
                                return o;
                            });
    }

    auto skipCurrentFrame() -> void
    {
        reader_->skipCurrentFrame();
    }

    // Seeking ----------------------------------------------------------------
    auto seekToFrame(double frameIndex) -> int
    {
        return static_cast<int>(reader_->seekToFrame(static_cast<uint64_t>(frameIndex)));
    }
    auto seekToTime(double timestampMs) -> int
    {
        return static_cast<int>(reader_->seekToTime(static_cast<uint64_t>(timestampMs)));
    }
    auto seekToZone(uint16_t zoneId) -> int
    {
        return static_cast<int>(reader_->seekToZone(zoneId));
    }

private:
    std::string                    path_;
    std::unique_ptr<xicap::Reader> reader_;
    xicap::ReadPacket              pkt_;
};

} // namespace

EMSCRIPTEN_BINDINGS(xicap_module)
{
    em::class_<JsReader>("Reader")
        .constructor<std::string>()
        .function("versionMajor", &JsReader::versionMajor)
        .function("versionMinor", &JsReader::versionMinor)
        .function("clientVersion", &JsReader::clientVersion)
        .function("captureAgent", &JsReader::captureAgent)
        .function("startZoneId", &JsReader::startZoneId)
        .function("endZoneId", &JsReader::endZoneId)
        .function("startWeather", &JsReader::startWeather)
        .function("startTimestampMs", &JsReader::startTimestampMs)
        .function("endTimestampMs", &JsReader::endTimestampMs)
        .function("durationMs", &JsReader::durationMs)
        .function("totalFrames", &JsReader::totalFrames)
        .function("totalPacketCount", &JsReader::totalPacketCount)
        .function("hasFooter", &JsReader::hasFooter)
        .function("lobby", &JsReader::lobby)
        .function("extensionTypes", &JsReader::extensionTypes)
        .function("getExtension", &JsReader::getExtension)
        .function("listZones", &JsReader::listZones)
        .function("next", &JsReader::next)
        .function("skipCurrentFrame", &JsReader::skipCurrentFrame)
        .function("seekToFrame", &JsReader::seekToFrame)
        .function("seekToTime", &JsReader::seekToTime)
        .function("seekToZone", &JsReader::seekToZone);

    em::enum_<xicap::PacketDirection>("PacketDirection")
        .value("ServerToClient", xicap::PacketDirection::ServerToClient)
        .value("ClientToServer", xicap::PacketDirection::ClientToServer);

    em::enum_<xicap::SeekResult>("SeekResult")
        .value("Ok", xicap::SeekResult::Ok)
        .value("EmptyIndex", xicap::SeekResult::EmptyIndex)
        .value("OutOfRange", xicap::SeekResult::OutOfRange)
        .value("NotFound", xicap::SeekResult::NotFound);

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

    em::enum_<xicap::ErrorCode>("ErrorCode")
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
        .value("AddMarkerWithoutPacket", xicap::ErrorCode::AddMarkerWithoutPacket);
}
