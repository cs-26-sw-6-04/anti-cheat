/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "targets.hpp"

using namespace ac;

/* Descendants of the protected root inherit protection via BPF's real_parent
 * ancestor walk: no per-pid API calls, so a hostile actor cannot shift the
 * protected set post-attach. */

TEST_CASE("memory enforcer blocks process_vm_readv against descendant",
          "[mem][subtree]") {
  run_scenario({
      .target = targets::flag_secret_nested(),
      .attack =
          [](const target_info &info) -> int {
        char buf[AC_FLAG_SIZE] = {0};
        iovec local{buf, sizeof(buf)};
        iovec remote{reinterpret_cast<void *>(info.addr),
                     std::min(info.len, sizeof(buf))};
        if (process_vm_readv(info.pid, &local, 1, &remote, 1, 0) < 0) {
          fprintf(stderr, "process_vm_readv: %s\n", std::strerror(errno));
          return 1;
        }
        buf[sizeof(buf) - 1] = '\0';
        fputs(buf, stdout);
        fflush(stdout);
        return 0;
      },
      .expect_enforcer = AC_ENF_MEMORY,
      .verify_success =
          [](target &t, const attack_result &r) {
            REQUIRE(r.stdout == t.info().flag);
          },
  });
}

TEST_CASE("memory enforcer blocks PTRACE_ATTACH against descendant",
          "[mem][subtree]") {
  run_scenario({
      .target = targets::flag_secret_nested(),
      .attack =
          [](const target_info &info) -> int {
        if (ptrace(PTRACE_ATTACH, info.pid, 0, 0) < 0) {
          fprintf(stderr, "ptrace(ATTACH, %u): %s\n", info.pid,
                  std::strerror(errno));
          return 1;
        }
        waitpid(info.pid, nullptr, 0);
        ptrace(PTRACE_DETACH, info.pid, 0, 0);
        return 0;
      },
      .expect_enforcer = AC_ENF_MEMORY,
      .verify_success =
          [](target &, const attack_result &) {
            /* ATTACH returning 0 is itself the capability under test. */
          },
  });
}

/* An unrelated process (outside the declared subtree) must not be covered
 * by mem. Without this, "protected subtree" would degenerate into "any
 * process" and the rodata-anchored narrowing would be meaningless. */
TEST_CASE("process outside protected subtree is not shielded",
          "[subtree][negative]") {
  /* Spawn the protected target first and open the session on its pid. */
  auto protected_target = targets::flag_secret()();
  auto sess = session::open_or_skip(protected_target.info().root_pid);

  /* Then spawn the outsider: a sibling of the protected target, a direct
   * child of the test harness (the "loader"). Its ancestor chain does not
   * pass through protected_root_pid, so mem must not fire on attacks
   * against it. */
  auto outsider = targets::flag_secret()();

  auto r = run_attacker(
      [](const target_info &info) -> int {
        char buf[AC_FLAG_SIZE] = {0};
        iovec local{buf, sizeof(buf)};
        iovec remote{reinterpret_cast<void *>(info.addr),
                     std::min(info.len, sizeof(buf))};
        if (process_vm_readv(info.pid, &local, 1, &remote, 1, 0) < 0) {
          fprintf(stderr, "process_vm_readv: %s\n", std::strerror(errno));
          return 1;
        }
        buf[sizeof(buf) - 1] = '\0';
        fputs(buf, stdout);
        fflush(stdout);
        return 0;
      },
      outsider.info());
  INFO("attacker stderr: " << r.stderr);
  REQUIRE(r.exit_code == 0);
  REQUIRE(r.stdout == outsider.info().flag);

  /* No deny event was emitted for this attack: if one fires, mem is
   * over-protecting. Drain briefly to catch a late event. */
  sess.drain();
  REQUIRE_FALSE(sess.next_event().has_value());
}
