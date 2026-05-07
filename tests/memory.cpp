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
#include "random.hpp"
#include "targets.hpp"

using namespace ac;

TEST_CASE("memory enforcer blocks process_vm_readv", "[mem][read]") {
  run_scenario({
      .target = targets::flag_secret(),
      .attack = [](const target_info &info) -> int {
        char buf[AC_FLAG_SIZE] = {0};
        iovec local{buf, sizeof(buf)};
        iovec remote{reinterpret_cast<void *>(info.addr),
                     std::min(info.len, sizeof(buf))};
        if (process_vm_readv(info.pid, &local, 1, &remote, 1, 0) < 0) {
          fprintf(stderr, "process_vm_readv: %s\n", std::strerror(errno));
          return 1;
        }
        /* Exfil the stolen bytes so the parent can verify they really match
         * the target's secret (not e.g. a zeroed buffer from a silent fail). */
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

TEST_CASE("memory enforcer blocks process_vm_writev", "[mem][write]") {
  auto payload = random_token();
  run_scenario({
      .target = targets::flag_secret(), // CTF{asda-asda-asda-asda}
      .attack = [payload](const target_info &info) -> int {
        char buf[AC_FLAG_SIZE] = {0};
        std::memcpy(buf, payload.data(),
                    std::min(payload.size(), sizeof(buf) - 1));
        iovec local{buf, sizeof(buf)};
        iovec remote{reinterpret_cast<void *>(info.addr),
                     std::min(info.len, sizeof(buf))};
        if (process_vm_writev(info.pid, &local, 1, &remote, 1, 0) < 0) {
          fprintf(stderr, "process_vm_writev: %s\n", std::strerror(errno));
          return 1;
        }
        return 0;
      },
      .expect_enforcer = AC_ENF_MEMORY,
      .verify_success =
          [payload](target &t, const attack_result &) {
            /* stop() closes target stdin and reads its "FLAG <value>" line. */
            t.stop();
            REQUIRE(t.observed_flag() == payload);
            REQUIRE(t.observed_flag() != t.info().flag);
          },
  });
}

TEST_CASE("memory enforcer blocks PTRACE_ATTACH", "[mem][attach]") {
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
      .expect_enforcer = AC_ENF_MEMORY,
      .verify_success =
          [](target &t, const attack_result &r) {
            REQUIRE(r.stdout == t.info().flag);
          },
  });
}
