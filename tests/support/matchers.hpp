/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include <sstream>
#include <string>

#include <catch2/matchers/catch_matchers_templated.hpp>

#include "ac.h"

namespace ac {

inline const char *enforcer_name(__u32 e) {
  switch (e) {
  case AC_ENF_SELFPROTECT:
    return "SELFPROTECT";
  case AC_ENF_MEMORY:
    return "MEMORY";
  default:
    return "?";
  }
}

struct FiredBy : Catch::Matchers::MatcherGenericBase {
  ac_enforcer enforcer;
  explicit FiredBy(ac_enforcer e) : enforcer(e) {}

  template <typename Deny> bool match(const Deny &d) const {
    return d.enforcer == static_cast<__u32>(enforcer);
  }

  std::string describe() const override {
    std::ostringstream os;
    os << "fired by enforcer=" << enforcer_name(enforcer);
    return os.str();
  }
};

} // namespace ac
