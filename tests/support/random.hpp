/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <string>

namespace ac {

/* Per-call unique printable token of the form "CTF{<16 hex chars>}", bounded
 * well under AC_FLAG_SIZE. Randomized so attackers cannot hardcode the value
 * and so initial/mutated tokens differ across runs. */
std::string random_token();

} // namespace ac
