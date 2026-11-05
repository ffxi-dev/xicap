#pragma once

#include "xicap/policy.h"

namespace xicap::policy
{

// Throws Error for a policy a writer refuses.
auto check(const ExclusionPolicy& policy) -> void;

} // namespace xicap::policy
