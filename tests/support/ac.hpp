/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include <array>
#include <functional>
#include <optional>

#include "ac.h"
#include "attacker.hpp"
#include "target.hpp"

namespace ac {

struct deny {
  __u32 enforcer;
  __u32 pid;
  __u32 target_pid;
  __s32 denied_errno;
};

class session {
public:
  session() = default;
  ~session();

  session(const session &) = delete;
  session &operator=(const session &) = delete;
  session(session &&) noexcept;
  session &operator=(session &&) noexcept;

  /* Opens a session protecting `protected_root_pid` and its descendants
   * (0 means selfprotect-only). Catch2 SKIPs on EPERM/EACCES (e.g., running
   * unprivileged). */
  static session open_or_skip(__u32 protected_root_pid = 0);

  std::optional<deny> next_event();
  int poll(int timeout_ms = 100);
  void drain();

#ifdef AC_DEBUG_BUILD
  void set_enabled(ac_enforcer id, bool on);
#endif

private:
  ac_session *s_ = nullptr;
  explicit session(ac_session *s) : s_(s) {}
};

#ifdef AC_DEBUG_BUILD
/* RAII: disables every user-facing enforcer except `keep`; restores on dtor.
 * SELFPROTECT is always on and not toggleable. */
class only_enforcer {
public:
  only_enforcer(session &s, ac_enforcer keep);
  ~only_enforcer();
  only_enforcer(const only_enforcer &) = delete;
  only_enforcer &operator=(const only_enforcer &) = delete;

private:
  session &s_;
  std::array<bool, AC_ENF__COUNT> prev_{};
};
#endif

/* Invoked in the "attack succeeds" SECTION after the attacker exits zero, with
 * the live target and the attacker's captured stdout/stderr. Must assert that
 * the attack actually achieved its effect (exfil matches, mutation landed,
 * etc.) — exit-code-only is not enough to distinguish a real hit from a
 * silently-failed syscall. */
using verify_success_fn = std::function<void(target &, const attack_result &)>;

struct scenario_spec {
  target_factory target;
  attacker_fn attack;
  ac_enforcer expect_enforcer;
  verify_success_fn verify_success;
};

/* Runs "attack succeeds (no enforcer)" + "protected" passes as Catch2 SECTIONs.
 * In the protected SECTION, opens a session with target.info().root_pid as
 * the subtree to guard. */
void run_scenario(const scenario_spec &spec);

} // namespace ac
