#include "xicap/dictionary.h"
#include "internal/dictionary_data.h"

namespace xicap
{

auto builtinDictionary() -> std::span<const uint8_t>
{
    return internal::BUILTIN_DICTIONARY_DATA;
}

} // namespace xicap
