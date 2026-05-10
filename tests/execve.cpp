/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "targets.hpp"

using namespace ac;

/* execve enforcer (lsm/bprm_check_security):
 * blocks exec from DESCENDANTS of the protected root; the root's own exec
 * (startup) is exempted (see design-decisions.md A2).
 * Attack originates inside the protected subtree via exec_child factory:
 * the root forks a grandchild (AFTER receiving the go-signal) that calls
 * execvp -- the grandchild is the descendant whose exec is blocked.
 *
 * SYNCHRONISATION: the root forks the grandchild only after t.release().
 * Test calls session::open_or_skip BEFORE t.release() so the enforcer is
 * active before the grandchild exists. */

TEST_CASE("execve enforcer blocks exec from protected subtree descendant",
          "[execve]") {
  SECTION("attack succeeds (no enforcer)") {
    auto t = targets::exec_child()();
    /* No session -- release immediately so root can fork grandchild. */
    t.release();
    t.stop(); /* reads FLAG line */
    REQUIRE(t.observed_flag() == "exec_ok");
  }

  SECTION("protected") {
    auto t = targets::exec_child()();
    /* Open session BEFORE releasing -- enforcer must be active before grandchild forks. */
    auto sess = session::open_or_skip(t.info().root_pid);
    t.release();  /* unblocks root; root forks grandchild under active session */

    /* Poll to collect the deny event from the grandchild's exec attempt. */
    sess.poll();
    sess.poll(); /* two polls to allow grandchild to run and event to land */
    t.stop();

    auto ev = sess.next_event();
    REQUIRE(ev.has_value());
    REQUIRE(ev->enforcer == AC_ENF_EXECVE);
    /* enforcer fires in the grandchild's context; pid is the grandchild.
     * We don't know the grandchild pid from the test harness (it is not
     * in the READY line), but it must differ from the root pid. */
    REQUIRE(ev->pid != t.info().root_pid);

    REQUIRE(t.observed_flag() == "exec_blocked");
  }
}

TEST_CASE("execve enforcer does not block root's own startup exec",
          "[execve][negative]") {
  /* Smoke test: a normal session where the target does no exec calls must
   * not produce any AC_ENF_EXECVE events. target::spawn() uses plain fork()
   * without exec, so the flag_secret child never calls exec after READY.
   * This test verifies the enforcer produces no spurious events during an
   * idle session — it does NOT exercise the me == ac_protected_root_pid
   * exemption path in execve.bpf.h (testing that exemption requires a target
   * that actually calls execvp so the root exemption branch is reached). */
  SECTION("root startup exec passes") {
    auto t = targets::flag_secret()();
    auto sess = session::open_or_skip(t.info().root_pid);

    /* Drain briefly to catch any stale event from session setup. */
    sess.drain();
    auto ev = sess.next_event();
    if (ev.has_value()) {
      REQUIRE(ev->enforcer != AC_ENF_EXECVE);
    }
    t.stop();
  }
}
