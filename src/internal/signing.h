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

[[nodiscard]] inline auto checkSignature(const PublicKey& key, const Signature& signature, std::span<const uint8_t> message) noexcept -> bool
{
    return crypto_ed25519_check(signature.data(), key.data(), message.data(), message.size()) == 0;
}

} // namespace xicap::internal
