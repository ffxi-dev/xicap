#pragma once

#include "internal/columns.h"
#include "xicap/types.h"

#include <optional/monocypher-ed25519.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

namespace xicap::internal
{

inline constexpr std::string_view CHECKPOINT_PREFIX = "xicap/4 checkpoint";
inline constexpr std::string_view FOOTER_PREFIX     = "xicap/4 footer";
inline constexpr std::string_view SEAL_PREFIX       = "xicap/4 seal";

// The signed stream (FORMAT.md, Signatures): one SHA-512 over the header, the
// blocks, and each packet's records.
class SignedStream
{
public:
    SignedStream() noexcept
    {
        crypto_sha512_init(&ctx_);
    }

    auto bytes(std::span<const uint8_t> b) noexcept -> void
    {
        crypto_sha512_update(&ctx_, b.data(), b.size());
    }

    auto marker(MarkerKind kind, std::string_view text) noexcept -> void
    {
        std::array<uint8_t, 4> head{ 'M', static_cast<uint8_t>(kind), 0, 0 };
        const auto             length = static_cast<uint16_t>(text.size());
        std::memcpy(head.data() + 2, &length, sizeof(length));
        bytes(head);
        bytes({ reinterpret_cast<const uint8_t*>(text.data()), text.size() });
    }

    auto packet(const Record& p) noexcept -> void
    {
        std::array<uint8_t, 18> head{ 'P' };
        const auto              length = static_cast<uint32_t>(p.data.size());
        std::memcpy(head.data() + 1, &p.timestamp, 8);
        std::memcpy(head.data() + 9, &p.flags, 2);
        head[11] = p.channel;
        std::memcpy(head.data() + 12, &p.opcode, 2);
        std::memcpy(head.data() + 14, &length, 4);
        bytes(head);
        bytes(p.data);
    }

    // D(k): the stream so far, which stays open.
    [[nodiscard]] auto digest() const noexcept -> Digest
    {
        auto   copy = ctx_;
        Digest out{};
        crypto_sha512_final(&copy, out.data());
        return out;
    }

    // D(end): the stream with its end record.
    [[nodiscard]] auto end(uint64_t totalPackets, uint64_t endTimestamp) const noexcept -> Digest
    {
        auto                    copy = ctx_;
        std::array<uint8_t, 17> record{ 'E' };
        std::memcpy(record.data() + 1, &totalPackets, 8);
        std::memcpy(record.data() + 9, &endTimestamp, 8);
        crypto_sha512_update(&copy, record.data(), record.size());
        Digest out{};
        crypto_sha512_final(&copy, out.data());
        return out;
    }

private:
    crypto_sha512_ctx ctx_{};
};

// prefix || parts..., the message a signature covers.
template <typename... Parts>
auto signedMessage(std::string_view prefix, const Parts&... parts) -> std::vector<uint8_t>
{
    std::vector<uint8_t> message(prefix.begin(), prefix.end());
    (message.insert(message.end(), std::begin(parts), std::end(parts)), ...);
    return message;
}

class SigningKey
{
public:
    explicit SigningKey(const SecretSeed& seed) noexcept
    {
        auto copy = seed; // Monocypher wipes the seed it is given
        crypto_ed25519_key_pair(secret_.data(), public_.data(), copy.data());
    }

    ~SigningKey()
    {
        crypto_wipe(secret_.data(), secret_.size());
    }

    SigningKey(const SigningKey&)                    = delete;
    SigningKey(SigningKey&&)                         = delete;
    auto operator=(const SigningKey&) -> SigningKey& = delete;
    auto operator=(SigningKey&&) -> SigningKey&      = delete;

    [[nodiscard]] auto publicKey() const noexcept -> const PublicKey&
    {
        return public_;
    }

    [[nodiscard]] auto sign(std::span<const uint8_t> message) const noexcept -> Signature
    {
        Signature signature{};
        crypto_ed25519_sign(signature.data(), secret_.data(), message.data(), message.size());
        return signature;
    }

private:
    std::array<uint8_t, 64> secret_{};
    PublicKey               public_{};
};

using Point = std::array<uint8_t, 32>;

consteval auto pointOf(std::string_view hex) -> Point
{
    const auto nibble = [](char c)
    {
        return static_cast<uint8_t>(c <= '9' ? c - '0' : c - 'a' + 10);
    };
    Point out{};
    for (size_t i = 0; i < out.size(); ++i)
    {
        out[i] = static_cast<uint8_t>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
    return out;
}

// RFC 8032's canonical encoding: y below p = 2^255 - 19, and no sign bit when x is 0, as it is for y = 1 and y = p - 1.
[[nodiscard]] inline auto canonical(std::span<const uint8_t, 32> point) noexcept -> bool
{
    static constexpr Point P         = pointOf("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    static constexpr Point P_MINUS_1 = pointOf("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    static constexpr Point ONE       = pointOf("0100000000000000000000000000000000000000000000000000000000000000");
    Point                  y{};
    std::ranges::copy(point, y.begin());
    y[31] &= 0x7F;
    const bool below = std::lexicographical_compare(y.rbegin(), y.rend(), P.rbegin(), P.rend()); // little-endian
    return below && ((point[31] & 0x80) == 0 || (y != ONE && y != P_MINUS_1));
}

// The eight points of small order, canonically encoded (FORMAT.md, Verifying a signature).
inline constexpr std::array<Point, 8> SMALL_ORDER{
    pointOf("0000000000000000000000000000000000000000000000000000000000000000"),
    pointOf("0000000000000000000000000000000000000000000000000000000000000080"),
    pointOf("0100000000000000000000000000000000000000000000000000000000000000"),
    pointOf("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    pointOf("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    pointOf("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    pointOf("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    pointOf("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
};

// Monocypher checks S < L and the group equation with the cofactor, but accepts non-canonical A and R and a
// small-order A; FORMAT.md, Verifying a signature, fails them.
[[nodiscard]] inline auto checkSignature(const PublicKey& key, const Signature& signature, std::span<const uint8_t> message) noexcept -> bool
{
    return canonical(key) && canonical(std::span{ signature }.first<32>()) && std::ranges::find(SMALL_ORDER, key) == SMALL_ORDER.end() &&
           crypto_ed25519_check(signature.data(), key.data(), message.data(), message.size()) == 0;
}

} // namespace xicap::internal
