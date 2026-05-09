/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "targets.hpp"

using namespace ac;

/* proc enforcer (lsm.s/file_open — sleepable):
 * Blocks open() on /proc/<protected_pid>/{status,cmdline,environ}, the three
 * paths not already blocked by ptrace_access_check (AC_ENF_MEMORY).
 * See docs/design-decisions.md A3 for the audit rationale.
 *
 * The attack is external: an attacker process opens a /proc/<pid>/ path.
 * run_scenario covers the "attack succeeds (no enforcer)" and "protected"
 * sections automatically. */

TEST_CASE("proc enforcer blocks open of /proc/<pid>/status",
          "[proc][status]") {
  run_scenario({
      .target = targets::flag_secret(),
      .attack = [](const target_info &info) -> int {
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%u/status", info.pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
          fprintf(stderr, "open(%s): %s\n", path, std::strerror(errno));
          return 1; /* open was blocked: attack failed */
        }
        close(fd);
        return 0; /* open succeeded: attack worked */
      },
      .expect_enforcer = AC_ENF_PROC,
      .verify_success = [](target &, const attack_result &) {
        /* open() returning >= 0 is the capability under test; no exfil needed. */
      },
  });
}

TEST_CASE("proc enforcer blocks open of /proc/<pid>/cmdline",
          "[proc][cmdline]") {
  run_scenario({
      .target = targets::flag_secret(),
      .attack = [](const target_info &info) -> int {
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%u/cmdline", info.pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
          fprintf(stderr, "open(%s): %s\n", path, std::strerror(errno));
          return 1;
        }
        close(fd);
        return 0;
      },
      .expect_enforcer = AC_ENF_PROC,
      .verify_success = [](target &, const attack_result &) {},
  });
}

TEST_CASE("proc enforcer blocks open of /proc/<pid>/environ",
          "[proc][environ]") {
  run_scenario({
      .target = targets::flag_secret(),
      .attack = [](const target_info &info) -> int {
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%u/environ", info.pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
          fprintf(stderr, "open(%s): %s\n", path, std::strerror(errno));
          return 1;
        }
        close(fd);
        return 0;
      },
      .expect_enforcer = AC_ENF_PROC,
      .verify_success = [](target &, const attack_result &) {},
  });
}
