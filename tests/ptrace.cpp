/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: MIT
 */

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <sys/ptrace.h>
#include <sys/wait.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "targets.hpp"

using namespace ac;

TEST_CASE("ptrace enforcer blocks PTRACE_ATTACH", "[ptrace][attach]") {
  run_scenario({
      .target = targets::flag_secret(),
      .attack =
          [](const target_info &info) -> int {
        if (ptrace(PTRACE_ATTACH, info.pid, 0, 0) < 0) {
          fprintf(stderr, "ptrace(ATTACH, %u): %s\n", info.pid,
                  std::strerror(errno));
          return 1;
        }
        waitpid(info.pid, nullptr, 0);
        /* Exfil memory via the debug channel to prove ATTACH actually gave us
         * control, not just returned zero. */
        char buf[AC_FLAG_SIZE] = {0};
        for (size_t i = 0; i + sizeof(long) <= info.len && i < sizeof(buf);
             i += sizeof(long)) {
          errno = 0;
          long word = ptrace(PTRACE_PEEKDATA, info.pid,
                             reinterpret_cast<void *>(info.addr + i), 0);
          if (errno != 0) {
            fprintf(stderr, "ptrace(PEEKDATA): %s\n", std::strerror(errno));
            ptrace(PTRACE_DETACH, info.pid, 0, 0);
            return 1;
          }
          std::memcpy(buf + i, &word, sizeof(word));
        }
        ptrace(PTRACE_DETACH, info.pid, 0, 0);
        buf[sizeof(buf) - 1] = '\0';
        fputs(buf, stdout);
        fflush(stdout);
        return 0;
      },
      .policy = AC_POLICY_BLOCK_PTRACE,
      .expect_enforcer = AC_ENF_PTRACE,
      .verify_success =
          [](target &t, const attack_result &r) {
            REQUIRE(r.stdout == t.info().flag);
          },
  });
}
