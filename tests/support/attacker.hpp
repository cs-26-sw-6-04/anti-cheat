/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include <functional>
#include <string>

#include "target.hpp"

namespace ac {

struct attack_result {
  int exit_code;
  std::string stdout;
  std::string stderr;
};

/* Runs in the forked attacker child. Returns exit code. */
using attacker_fn = std::function<int(const target_info &)>;

attack_result run_attacker(const attacker_fn &fn, const target_info &info);

} // namespace ac
