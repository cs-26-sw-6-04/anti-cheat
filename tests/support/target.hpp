/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <sys/types.h>

#include "ac.h"

namespace ac {

struct target_info {
  __u32 pid;
  uintptr_t addr;
  size_t len;
  std::string flag;
};

/* target_fn runs in the child after fork(). stdin/stdout are already pipes.
 * Protocol: print "READY <pid> <addr> <len>\n" + flush, read until stdin EOF,
 * print "FLAG <value>\n" + flush, return exit code. */
using target_fn = std::function<int()>;

class target {
public:
  target() = default;
  ~target();

  target(const target &) = delete;
  target &operator=(const target &) = delete;
  target(target &&) noexcept;
  target &operator=(target &&) noexcept;

  static target spawn(target_fn fn);
  static target existing(__u32 pid, uintptr_t addr, size_t len);

  const target_info &info() const { return info_; }
  /* Set by factories when the initial secret is known up front. Attacker-side
   * reads are verified against this value. */
  void set_flag(std::string flag) { info_.flag = std::move(flag); }
  /* FLAG <value> line captured by stop(); empty until stop() has been called.
   * Used to verify writev-style attacks actually mutated the target's buffer. */
  const std::string &observed_flag() const { return observed_flag_; }
  void stop();

private:
  target_info info_{};
  std::string observed_flag_;
  pid_t child_pid_ = 0;
  int stdin_fd_ = -1;
  FILE *stdout_ = nullptr;
  bool stopped_ = false;

  void terminate();
};

using target_factory = std::function<target()>;

} // namespace ac
