#pragma once

#include <cstdint>

namespace mhr_early_hook_probe {

void set_attach_tick(std::uint64_t tick);
void initialize();

} // namespace mhr_early_hook_probe
