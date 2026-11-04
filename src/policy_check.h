#pragma once

#include "xicap/policy.h"

namespace xicap::internal
{

// Throws Error for a policy a writer refuses.
auto checkPolicy(const ExclusionPolicy& policy) -> void;

} // namespace xicap::internal
