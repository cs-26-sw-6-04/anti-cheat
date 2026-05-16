/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Each test mirrors a technique from a public cheat, with a citation to
 * the upstream snippet. The dlopen test links the vendored linux-inject
 * (GPL-2.0+), so this file is GPL-2.0-only.
 */

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "random.hpp"
#include "targets.hpp"

#if HAVE_LINUX_INJECT
#  include "linux_inject_lib.h"
#  include "real_cheat_payload_path.h"
#endif

using namespace ac;

/* Cite: deadlocked src/os/process.rs#L78-L94 (GPL-3.0). Read remote
 * process memory via process_vm_readv.
 * https://github.com/avitran0/deadlocked/blob/2d07cd060822306fb1e7412fedbe0159e6099ca3/src/os/process.rs#L78-L94
 */
TEST_CASE("real-cheat: deadlocked process_vm_readv",
          "[real-cheat][deadlocked][read][process-vm]") {
  run_scenario({
      .target = targets::flag_secret(),
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

/* Cite: deadlocked src/os/process.rs#L220-L224 (GPL-3.0). Read remote
 * process memory via /proc/<pid>/mem pread, a distinct kernel path from
 * process_vm_readv.
 * https://github.com/avitran0/deadlocked/blob/2d07cd060822306fb1e7412fedbe0159e6099ca3/src/os/process.rs#L220-L224
 */
TEST_CASE("real-cheat: deadlocked /proc/<pid>/mem pread",
          "[real-cheat][deadlocked][read][procmem]") {
  run_scenario({
      .target = targets::flag_secret(),
      .attack =
          [](const target_info &info) -> int {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%u/mem", info.pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
          fprintf(stderr, "open(%s): %s\n", path, std::strerror(errno));
          return 1;
        }
        char buf[AC_FLAG_SIZE] = {0};
        size_t want = std::min(info.len, sizeof(buf));
        ssize_t got = pread(fd, buf, want, static_cast<off_t>(info.addr));
        close(fd);
        if (got <= 0) {
          fprintf(stderr, "pread: %s\n", std::strerror(errno));
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

/* Cite: xenon-cheats injection_service.cpp#L52 (MIT). Write bytes (the
 * DLL path) into a remote process via WriteProcessMemory. Wine maps this
 * to process_vm_writev on Linux.
 * https://github.com/kiocode/xenon-cheats/blob/dd221d076a30707e25c438b3bac9c40eadd6a83d/xenon/src/components/services/injection_service.cpp#L52
 */
TEST_CASE("real-cheat: xenon WriteProcessMemory (process_vm_writev)",
          "[real-cheat][xenon][write][process-vm]") {
  auto payload = random_token();
  run_scenario({
      .target = targets::flag_secret(),
      .attack =
          [payload](const target_info &info) -> int {
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
            t.stop();
            REQUIRE(t.observed_flag() == payload);
            REQUIRE(t.observed_flag() != t.info().flag);
          },
  });
}

/* Cite: xenon-cheats injection_service.cpp#L101 (MIT). CreateProcess
 * with CREATE_SUSPENDED. The Linux equivalent for an already-running
 * target is PTRACE_SEIZE + PTRACE_INTERRUPT (silent suspend, no SIGSTOP).
 * https://github.com/kiocode/xenon-cheats/blob/dd221d076a30707e25c438b3bac9c40eadd6a83d/xenon/src/components/services/injection_service.cpp#L101
 */
TEST_CASE("real-cheat: xenon CREATE_SUSPENDED (PTRACE_SEIZE blocked on target)",
          "[real-cheat][xenon][ptrace][create-suspended]") {
  run_scenario({
      .target = targets::flag_secret(),
      .attack =
          [](const target_info &info) -> int {
        if (ptrace(PTRACE_SEIZE, info.pid, 0, 0) < 0) {
          fprintf(stderr, "ptrace(SEIZE, %u): %s\n", info.pid,
                  std::strerror(errno));
          return 1;
        }
        if (ptrace(PTRACE_INTERRUPT, info.pid, 0, 0) < 0) {
          fprintf(stderr, "ptrace(INTERRUPT, %u): %s\n", info.pid,
                  std::strerror(errno));
          ptrace(PTRACE_DETACH, info.pid, 0, 0);
          return 1;
        }
        waitpid(info.pid, nullptr, 0);
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
      .protected_stderr_contains = "ptrace(SEIZE",
  });
}

/* Same cite. The AC loader must also reject PTRACE_SEIZE. */
TEST_CASE("real-cheat: xenon CREATE_SUSPENDED (PTRACE_SEIZE blocked on AC loader)",
          "[real-cheat][xenon][ptrace][create-suspended][self-protect]") {
  run_scenario({
      .target = targets::ac_self(),
      .attack =
          [](const target_info &info) -> int {
        if (ptrace(PTRACE_SEIZE, info.pid, 0, 0) < 0) {
          fprintf(stderr, "ptrace(SEIZE, %u): %s\n", info.pid,
                  std::strerror(errno));
          return 1;
        }
        if (ptrace(PTRACE_INTERRUPT, info.pid, 0, 0) < 0) {
          fprintf(stderr, "ptrace(INTERRUPT, %u): %s\n", info.pid,
                  std::strerror(errno));
          ptrace(PTRACE_DETACH, info.pid, 0, 0);
          return 1;
        }
        waitpid(info.pid, nullptr, 0);
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
      .expect_enforcer = AC_ENF_SELFPROTECT,
      .verify_success =
          [](target &t, const attack_result &r) {
            REQUIRE(r.stdout == t.info().flag);
          },
      .protected_stderr_contains = "ptrace(SEIZE",
  });
}

/* Cite: xenon-cheats injection_service.cpp#L78-L91 (MIT). Full DLL
 * injection (LoadLibraryDLL or ManualMapDLL). The Linux equivalent is
 * ptrace + write + SETREGS-to-dlopen; this test links the vendored
 * gaffe23/linux-inject (GPL-2.0+) to drive the full chain.
 * https://github.com/kiocode/xenon-cheats/blob/dd221d076a30707e25c438b3bac9c40eadd6a83d/xenon/src/components/services/injection_service.cpp#L78-L91
 */
TEST_CASE("real-cheat: xenon LoadLibraryDLL/ManualMap (dlopen injection chain "
          "severed at PTRACE_ATTACH)",
          "[real-cheat][xenon][inject][dlopen]") {
#if !HAVE_LINUX_INJECT
  SKIP("skipping real-cheat injection test: arch not supported by vendored "
       "linux-inject");
#else
  if (!dlsym(RTLD_DEFAULT, "dlopen")) {
    SKIP("skipping real-cheat injection test: dlopen not resolvable in libc");
  }
  run_scenario({
      .target = targets::flag_secret(),
      .attack =
          [](const target_info &info) -> int {
        int errnum = 0;
        if (linux_inject_so(info.pid, REAL_CHEAT_PAYLOAD_SO_PATH, &errnum) !=
            0) {
          fprintf(stderr, "linux_inject_so: rc=%d\n", errnum);
          return 1;
        }
        /* Upstream linux-inject returns 0 even when checkloaded() reports
         * "could not inject"; verify the .so is actually mapped before
         * claiming success. */
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", info.pid);
        FILE *f = fopen(maps_path, "r");
        if (!f)
          return 2;
        char line[1024];
        int hit = 0;
        while (fgets(line, sizeof(line), f)) {
          if (std::strstr(line, "real_cheat_payload.so")) {
            hit = 1;
            break;
          }
        }
        fclose(f);
        if (!hit)
          return 3;
        fputs("INJECT_OK real_cheat_payload.so\n", stdout);
        fflush(stdout);
        return 0;
      },
      .expect_enforcer = AC_ENF_MEMORY,
      .verify_success =
          [](target &, const attack_result &r) {
            REQUIRE(r.stdout.find("INJECT_OK real_cheat_payload.so") !=
                    std::string::npos);
          },
      /* upstream emits this when ptrace(PTRACE_ATTACH) fails; pins the
       * block at the chain entry, not a later step. */
      .protected_stderr_contains = "ptrace(PTRACE_ATTACH) failed",
      /* Upstream's shellcode-based injection greps /proc/PID/maps for
       * "libc" to find its base, then writes a call to dlopen at a
       * computed offset. With Debug ac_tests the first matching line
       * is not the real libc, so the call lands wrong and the target
       * segfaults before the expected int3. Skip the no-enforcer
       * SECTION in that case; the AC-blocking SECTION still runs. */
      .flaky_skip_no_enforcer_stderr = "expected SIGTRAP",
  });
#endif
}

/* SCOPE.md §Residual Weaknesses #1: once bpf_link fds close, the LSM is
 * detached. The race window between loader death and PR_SET_PDEATHSIG
 * delivery is sub-microsecond and host-dependent, so the test exercises
 * the underlying property: with the session closed, reads succeed. */
TEST_CASE("real-cheat: root reads target after loader drops enforcement",
          "[real-cheat][root][residual]") {
  auto t = targets::flag_secret()();
  {
    auto sess = session::open_or_skip(t.info().root_pid);
    (void)sess;
  }
  /* sess destructor closed the bpf_link fds; LSM is detached. */

  char buf[AC_FLAG_SIZE] = {0};
  iovec local{buf, sizeof(buf)};
  iovec remote{reinterpret_cast<void *>(t.info().addr),
               std::min(t.info().len, sizeof(buf))};
  ssize_t got = process_vm_readv(t.info().pid, &local, 1, &remote, 1, 0);
  REQUIRE(got > 0);
  buf[sizeof(buf) - 1] = '\0';
  REQUIRE(std::string(buf) == t.info().flag);
}
