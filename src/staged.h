#pragma once

#include <filesystem>
#include <format>
#include <random>

namespace xicap::internal
{

// A file beside dst that becomes dst only once whole: a failed call leaves dst as it was.
class Staged
{
public:
    explicit Staged(std::filesystem::path dst)
    : dst_(std::move(dst))
    {
        std::random_device rd;
        path_ = std::filesystem::path(dst_).concat(std::format(".{:08x}{:08x}.tmp", rd(), rd()));
    }

    ~Staged()
    {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    Staged(const Staged&)                    = delete;
    Staged(Staged&&)                         = delete;
    auto operator=(const Staged&) -> Staged& = delete;
    auto operator=(Staged&&) -> Staged&      = delete;

    [[nodiscard]] auto path() const noexcept -> const std::filesystem::path&
    {
        return path_;
    }

    auto publish() const -> void
    {
        std::filesystem::rename(path_, dst_);
    }

private:
    std::filesystem::path dst_;
    std::filesystem::path path_;
};

} // namespace xicap::internal
