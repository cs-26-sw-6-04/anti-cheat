/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "targets.hpp"

using namespace ac;

/* scanmem (and so gameconqueror) reads memory by combining PTRACE_ATTACH with
 * /proc/<pid>/mem + pread, not just one of the two:
 *   1. ptrace(PTRACE_ATTACH, pid)         — stops the target, ptracer = us
 *   2. waitpid(pid, ..., 0)               — wait for the SIGSTOP
 *   3. open("/proc/<pid>/mem", O_RDWR)    — cred-snapshotted fd, future reads
 *                                            do not re-enter ptrace_access_check
 *   4. pread(fd, ...) loop                — reads via cached fd's mm
 *   5. ptrace(PTRACE_DETACH, pid, 1, 0)
 *
 * See scanmem/ptrace.c:97 (sm_attach) and scanmem/ptrace.c:175 (readmemory).
 *
 * The memory enforcer must deny somewhere in steps 1-3; once the proc-mem fd
 * is open, the kernel does not consult ptrace_access_check on subsequent
 * pread()s. */
TEST_CASE("memory enforcer blocks scanmem-style attach + /proc/<pid>/mem read",
          "[mem][scanmem]") {
  run_scenario({
      .target = targets::flag_secret(),
      .attack = [](const target_info &info) -> int {
        if (ptrace(PTRACE_ATTACH, info.pid, 0, 0) < 0) {
          fprintf(stderr, "ptrace(ATTACH, %u): %s\n", info.pid,
                  std::strerror(errno));
          return 1;
        }
        int status = 0;
        if (waitpid(info.pid, &status, 0) < 0 || !WIFSTOPPED(status)) {
          fprintf(stderr, "waitpid: %s (status=0x%x)\n", std::strerror(errno),
                  status);
          ptrace(PTRACE_DETACH, info.pid, 0, 0);
          return 1;
        }

        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%u/mem", info.pid);
        int fd = open(path, O_RDWR);
        if (fd < 0) {
          fprintf(stderr, "open(%s): %s\n", path, std::strerror(errno));
          ptrace(PTRACE_DETACH, info.pid, 1, 0);
          return 1;
        }

        char buf[AC_FLAG_SIZE] = {0};
        size_t want = std::min(info.len, sizeof(buf) - 1);
        ssize_t got = pread(fd, buf, want, static_cast<off_t>(info.addr));
        close(fd);
        ptrace(PTRACE_DETACH, info.pid, 1, 0);
        if (got <= 0) {
          fprintf(stderr, "pread: %s (got=%zd)\n", std::strerror(errno), got);
          return 1;
        }
        buf[got] = '\0';
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
