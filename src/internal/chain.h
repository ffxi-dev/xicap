#pragma once

#include "xicap/types.h"

#include <optional/monocypher-ed25519.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace xicap::internal
{

inline constexpr std::string_view CHECKPOINT_PREFIX = "xicap/3 checkpoint";
inline constexpr std::string_view FOOTER_PREFIX     = "xicap/3 footer";

// The SHA-512 hash chain of FORMAT.md's Signatures section. Each block is
// absorbed as h = SHA-512(h || block); a block may arrive in pieces between
// begin() and end().
class Chain
{
public:
    auto start(std::span<const uint8_t> header) noexcept -> void
    {
        crypto_sha512(value_.data(), header.data(), header.size());
    }

    auto begin() noexcept -> void
    {
        crypto_sha512_init(&ctx_);
        crypto_sha512_update(&ctx_, value_.data(), value_.size());
    }

    auto update(std::span<const uint8_t> bytes) noexcept -> void
    {
        crypto_sha512_update(&ctx_, bytes.data(), bytes.size());
    }

    auto end() noexcept -> void
    {
        crypto_sha512_final(&ctx_, value_.data());
    }

    auto absorb(std::span<const uint8_t> block) noexcept -> void
    {
        begin();
        update(block);
        end();
    }

    [[nodiscard]] auto value() const noexcept -> const ChainValue&
    {
        return value_;
    }

private:
    ChainValue        value_{};
    crypto_sha512_ctx ctx_{};
};

// prefix || chain, in a buffer sized for the longer prefix. Only the first
// prefix.size() + 64 bytes are the message.
inline auto signedMessage(std::string_view prefix, const ChainValue& chain) -> std::array<uint8_t, 82>
{
    static_assert(CHECKPOINT_PREFIX.size() + 64 == 82);
    std::array<uint8_t, 82> message{};
    std::copy(prefix.begin(), prefix.end(), message.begin());
    std::copy(chain.begin(), chain.end(), message.begin() + static_cast<std::ptrdiff_t>(prefix.size()));
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

    [[nodiscard]] auto sign(std::string_view prefix, const ChainValue& chain) const noexcept -> Signature
    {
        const auto message = signedMessage(prefix, chain);
        Signature  signature{};
        crypto_ed25519_sign(signature.data(), secret_.data(), message.data(), prefix.size() + chain.size());
        return signature;
    }

private:
    std::array<uint8_t, 64> secret_{};
    PublicKey               public_{};
};

[[nodiscard]] inline auto checkSignature(const PublicKey& key, const Signature& signature, std::string_view prefix, const ChainValue& chain) noexcept -> bool
{
    const auto message = signedMessage(prefix, chain);
    return crypto_ed25519_check(signature.data(), key.data(), message.data(), prefix.size() + chain.size()) == 0;
}

} // namespace xicap::internal
