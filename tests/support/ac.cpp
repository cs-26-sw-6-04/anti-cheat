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

session session::open_or_skip(__u32 protected_root_pid) {
  /* Allow siblings / children to ptrace us in self-protect scenarios. */
  (void)prctl(PR_SET_PTRACER, static_cast<unsigned long>(-1), 0, 0, 0);

  /* Keep descendants of the test-harness-as-loader reparented within us.
   * Production loaders should do the equivalent before ac_open; see SCOPE.md.
   */
  (void)prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

  ac_session *s = nullptr;
  int err = ac_open(&s, protected_root_pid);
  if (err == -EPERM || err == -EACCES) {
    SKIP("skipping live BPF test: insufficient privileges: " +
         std::string(std::strerror(-err)));
  }
  REQUIRE(err == 0);
  return session(s);
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
    auto t = spec.target();
    auto sess = session::open_or_skip(t.info().root_pid);

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
