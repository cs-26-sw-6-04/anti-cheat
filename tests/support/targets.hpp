/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "target.hpp"

namespace ac::targets {

/* Child process holds a buffer initialized to a freshly-randomized token (set
 * on the returned target's info.flag), announces its pid + address + size via
 * READY, blocks until stdin EOF, then prints FLAG <value>. */
target_factory flag_secret();

/* "Target" is the current process — used by self-protect tests where AC's own
 * pid is the victim. No fork. The dummy buffer is primed with a fresh random
 * token, surfaced via info.flag so attackers can be verified. */
target_factory ac_self();

} // namespace ac::targets
