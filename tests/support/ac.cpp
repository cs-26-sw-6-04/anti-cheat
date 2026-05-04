/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "ac.hpp"

#include <cerrno>
#include <cstring>
#include <string>

#include <sys/prctl.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers.hpp>

#include "matchers.hpp"

namespace ac {

session::~session() {
  if (s_)
    ac_close(s_);
}

session::session(session &&o) noexcept : s_(o.s_) { o.s_ = nullptr; }

session &session::operator=(session &&o) noexcept {
  if (this != &o) {
    if (s_)
      ac_close(s_);
    s_ = o.s_;
    o.s_ = nullptr;
  }
  return *this;
}

session session::open_or_skip() {
  /* Allow siblings / children to ptrace us in self-protect scenarios. */
  (void)prctl(PR_SET_PTRACER, static_cast<unsigned long>(-1), 0, 0, 0);

  ac_session *s = nullptr;
  int err = ac_open(&s);
  if (err == -EPERM || err == -EACCES) {
    SKIP("skipping live BPF test: insufficient privileges: " +
         std::string(std::strerror(-err)));
  }
  REQUIRE(err == 0);
  return session(s);
}

void session::protect(__u32 pid, __u32 policy) {
  REQUIRE(s_);
  REQUIRE(ac_protect(s_, pid, policy) == 0);
}

void session::unprotect(__u32 pid) {
  REQUIRE(s_);
  REQUIRE(ac_unprotect(s_, pid) == 0);
}

void session::whitelist(__u32 pid) {
  REQUIRE(s_);
  REQUIRE(ac_whitelist_add(s_, pid) == 0);
}

void session::unwhitelist(__u32 pid) {
  REQUIRE(s_);
  REQUIRE(ac_whitelist_remove(s_, pid) == 0);
}

std::optional<deny> session::next_event() {
  REQUIRE(s_);
  ac_event e{};
  int err = ac_next_event(s_, &e);
  if (err == -EAGAIN)
    return std::nullopt;
  REQUIRE(err == 0);
  return deny{e.enforcer, e.pid, e.target_pid, e.denied_errno};
}

int session::poll(int timeout_ms) {
  REQUIRE(s_);
  int n = ac_poll(s_, timeout_ms);
  REQUIRE((n >= 0 || n == -EINTR));
  return n;
}

void session::drain() {
  for (int i = 0; i < 5; ++i)
    poll(50);
}

#ifdef AC_DEBUG_BUILD
void session::set_enabled(ac_enforcer id, bool on) {
  REQUIRE(s_);
  REQUIRE(ac_set_enforcer_enabled(s_, id, on ? 1 : 0) == 0);
}

only_enforcer::only_enforcer(session &s, ac_enforcer keep) : s_(s) {
  /* Snapshot + disable all user-facing enforcers except `keep`. */
  for (int i = 1; i < AC_ENF__COUNT; ++i) {
    if (i == AC_ENF_SELFPROTECT)
      continue;
    prev_[i] = true;
    s_.set_enabled(static_cast<ac_enforcer>(i),
                   static_cast<ac_enforcer>(i) == keep);
  }
}

only_enforcer::~only_enforcer() {
  for (int i = 1; i < AC_ENF__COUNT; ++i) {
    if (i == AC_ENF_SELFPROTECT)
      continue;
    s_.set_enabled(static_cast<ac_enforcer>(i), prev_[i]);
  }
}
#endif

void run_scenario(const scenario_spec &spec) {
  REQUIRE(spec.verify_success);

  SECTION("attack succeeds (no enforcer)") {
    auto t = spec.target();
    auto r = run_attacker(spec.attack, t.info());
    INFO("attacker stderr: " << r.stderr);
    REQUIRE(r.exit_code == 0);
    spec.verify_success(t, r);
    t.stop();
  }

  SECTION("protected") {
    auto sess = session::open_or_skip();
#ifdef AC_DEBUG_BUILD
    only_enforcer guard(sess, spec.expect_enforcer);
#endif
    auto t = spec.target();
    if (spec.policy != 0)
      sess.protect(t.info().pid, spec.policy);

    auto r = run_attacker(spec.attack, t.info());
    INFO("protected stderr: " << r.stderr);
    REQUIRE(r.exit_code != 0);

    sess.poll();
    auto ev = sess.next_event();
    REQUIRE(ev.has_value());
    REQUIRE_THAT(*ev, FiredBy(spec.expect_enforcer));
    REQUIRE(ev->target_pid == t.info().pid);

    t.stop();
  }
}

} // namespace ac
