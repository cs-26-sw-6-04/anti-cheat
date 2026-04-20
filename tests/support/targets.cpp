/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "targets.hpp"

#include <cstdio>
#include <cstring>
#include <string>

#include <sys/prctl.h>
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
    return t;
  };
}

} // namespace ac::targets
