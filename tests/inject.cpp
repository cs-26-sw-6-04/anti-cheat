/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <sys/mman.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "targets.hpp"

using namespace ac;

/* inject enforcer (lsm/mmap_file):
 * blocks anonymous PROT_EXEC mmap from within the protected subtree.
 * The attack originates INSIDE the protected process (mmap maps into the
 * caller's own address space; there is no external attacker). The test
 * uses the mmap_exec_self() target factory whose target_fn blocks after
 * READY waiting for t.release(), then performs the mmap.
 *
 * SYNCHRONISATION: the target waits for t.release() before calling mmap.
 * In the "protected" section, session::open_or_skip is called BEFORE
 * t.release() so the enforcer is active when the mmap fires. */

TEST_CASE("inject enforcer blocks anonymous PROT_EXEC mmap", "[inject][mmap]") {
  SECTION("attack succeeds (no enforcer)") {
    auto t = targets::mmap_exec_self()();
    /* No session -- release immediately so target can proceed to mmap. */
    t.release();
    t.stop(); /* reads FLAG line; target exits 0 on success */
    REQUIRE(t.observed_flag() == "mmap_ok");
  }

  SECTION("protected") {
    auto t = targets::mmap_exec_self()();
    /* Open session BEFORE releasing the target -- enforcer must be active
     * before the mmap call fires. */
    auto sess = session::open_or_skip(t.info().root_pid);
    t.release();  /* unblocks target; target now calls mmap under active session */

    /* Drain the ring buffer to collect the deny event. */
    sess.poll();
    t.stop(); /* reads FLAG line; target exits 1 (mmap was blocked) */

    auto ev = sess.next_event();
    REQUIRE(ev.has_value());
    REQUIRE(ev->enforcer == AC_ENF_INJECT);
    /* For inject, the attacker and victim are the same process. */
    REQUIRE(ev->pid == t.info().pid);
    REQUIRE(ev->target_pid == t.info().pid);

    REQUIRE(t.observed_flag() == "mmap_blocked");
  }
}

/* Smoke test: a normal session where the target does no mmap(PROT_EXEC) calls
 * must not produce any AC_ENF_INJECT events. target::spawn() uses plain fork()
 * without exec, so the child inherits the parent's already-mapped address space
 * and ld.so does not run; there are no file-backed PROT_EXEC mappings in the
 * child. This test therefore verifies that the enforcer produces no spurious
 * events during an idle session — it does NOT exercise the file != NULL exemption
 * in inject.bpf.h (testing that exemption requires a target that actually execs
 * a binary so ld.so maps shared libraries). */
TEST_CASE("inject enforcer: no spurious events during normal session (smoke)",
          "[inject][mmap][negative]") {
  SECTION("normal session -- no inject events") {
    auto t = targets::flag_secret()();
    auto sess = session::open_or_skip(t.info().root_pid);

    sess.drain();
    /* No inject event should exist from startup library loads. */
    auto ev = sess.next_event();
    if (ev.has_value()) {
      REQUIRE(ev->enforcer != AC_ENF_INJECT);
    }
    t.stop();
  }
}
