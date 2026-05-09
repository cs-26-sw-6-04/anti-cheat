/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "targets.hpp"

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <system_error>

#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "random.hpp"

namespace ac::targets {

target_factory flag_secret() {
  return []() {
    std::string initial = random_token();
    auto t = target::spawn([initial] {
      /* Allow sibling attacker to ptrace us under Yama ptrace_scope=1. */
      (void)prctl(PR_SET_PTRACER, static_cast<unsigned long>(-1), 0, 0, 0);

      static char secret[AC_FLAG_SIZE];
      std::memset(secret, 0, sizeof(secret));
      std::memcpy(secret, initial.data(),
                  std::min(initial.size(), sizeof(secret) - 1));

      printf("READY %u %llx %zu\n", (unsigned)getpid(),
             (unsigned long long)(uintptr_t)secret, sizeof(secret));
      fflush(stdout);

      while (getchar() != EOF) {
      }

      printf("FLAG %s\n", secret);
      fflush(stdout);
      return 0;
    });
    t.set_flag(initial);
    t.set_root_pid(t.info().pid);
    return t;
  };
}

target_factory flag_secret_nested() {
  return []() {
    std::string initial = random_token();
    auto t = target::spawn([initial] {
      /* Intermediate subtree root. Hold SIGCHLD reaping so the grandchild
       * stays alive for the test. Be a subreaper so reparented descendants
       * stay inside the subtree if anything in between dies. */
      (void)prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
      (void)prctl(PR_SET_PTRACER, static_cast<unsigned long>(-1), 0, 0, 0);

      int barrier[2];
      if (pipe(barrier) != 0) {
        fprintf(stderr, "nested: pipe: %s\n", std::strerror(errno));
        return 1;
      }

      pid_t gc = fork();
      if (gc < 0) {
        fprintf(stderr, "nested: fork: %s\n", std::strerror(errno));
        return 1;
      }

      if (gc == 0) {
        /* Grandchild dies if the intermediate parent dies, which itself dies
         * if the loader dies (see SCOPE.md). */
        (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        (void)prctl(PR_SET_PTRACER, static_cast<unsigned long>(-1), 0, 0, 0);
        close(barrier[0]);

        static char secret[AC_FLAG_SIZE];
        std::memset(secret, 0, sizeof(secret));
        std::memcpy(secret, initial.data(),
                    std::min(initial.size(), sizeof(secret) - 1));

        printf("READY %u %llx %zu\n", (unsigned)getpid(),
               (unsigned long long)(uintptr_t)secret, sizeof(secret));
        fflush(stdout);

        close(barrier[1]); /* Signal intermediate to wait on stdin. */

        while (getchar() != EOF) {
        }

        printf("FLAG %s\n", secret);
        fflush(stdout);
        _exit(0);
      }

      close(barrier[1]);
      char b;
      (void)read(barrier[0], &b, 1);
      close(barrier[0]);

      /* Stay alive while the grandchild runs; reap it when it exits. */
      int status = 0;
      (void)waitpid(gc, &status, 0);
      return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    });
    t.set_flag(initial);
    /* info.pid is the grandchild (from READY). The intermediate child is the
     * subtree root we protect. */
    t.set_root_pid(t.spawned_pid());
    return t;
  };
}

target_factory ac_self() {
  return [] {
    /* Allow anyone to ptrace this (the AC loader) process. */
    (void)prctl(PR_SET_PTRACER, static_cast<unsigned long>(-1), 0, 0, 0);
    static char dummy[AC_FLAG_SIZE];
    std::string initial = random_token();
    std::memset(dummy, 0, sizeof(dummy));
    std::memcpy(dummy, initial.data(),
                std::min(initial.size(), sizeof(dummy) - 1));
    auto t = target::existing((__u32)getpid(), (uintptr_t)dummy, sizeof(dummy));
    t.set_flag(initial);
    /* root_pid = 0 by default: self-protect tests run without subtree
     * registration; selfprotect covers the loader pid via rodata. */
    return t;
  };
}

target_factory mmap_exec_self() {
  return []() {
    auto t = target::spawn([] {
      /* Allow sibling attacker to ptrace us (matches flag_secret pattern). */
      (void)prctl(PR_SET_PTRACER, static_cast<unsigned long>(-1), 0, 0, 0);

      /* Print READY. addr=0, len=0 -- this target has no secret buffer;
       * the enforcement signal is the mmap result, not a data exfil. */
      printf("READY %u 0 0\n", (unsigned)getpid());
      fflush(stdout);

      /* SYNCHRONISATION: block until the test writes the "go" signal byte.
       * This ensures the session is open before the mmap is attempted.
       * getchar() reads the single byte written by t.release(). */
      getchar();

      /* Perform the inject attack from inside the protected process.
       * The enforcer fires on this call when a session is active. */
      void *p = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
      int blocked = (p == MAP_FAILED) ? 1 : 0;
      if (p != MAP_FAILED)
        munmap(p, 4096);

      /* Wait for stop() to close stdin (EOF) before printing FLAG. */
      while (getchar() != EOF) {
      }

      /* FLAG line encodes the outcome. "mmap_ok" = succeeded (no enforcer).
       * "mmap_blocked" = denied (enforcer active). */
      printf("FLAG %s\n", blocked ? "mmap_blocked" : "mmap_ok");
      fflush(stdout);
      return blocked; /* 0 = attack succeeded (no enforcer); 1 = blocked */
    });
    /* root_pid == pid: the target process is its own subtree root. */
    t.set_root_pid(t.info().pid);
    t.set_flag("mmap_ok"); /* expected flag when no enforcer */
    return t;
  };
}

} // namespace ac::targets
