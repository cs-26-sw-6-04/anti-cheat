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
  /* The pid the attack targets (process_vm_readv/writev, ptrace). */
  __u32 pid;
  /* The pid to pass to ac_open as the protected subtree root. Usually equals
   * `pid` (single-process target). Differs for nested targets where the
   * subtree root spawns a descendant that holds the victim state; then
   * `pid` is the descendant and `root_pid` is the subtree root. 0 means
   * "open without subtree protection" (selfprotect-only, used by the ac_self
   * target factory). */
  __u32 root_pid;
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
  /* Set by factories to declare which pid the ac_session should protect as
   * the subtree root. For single-process targets this is info.pid; for nested
   * targets it is the intermediate spawned pid (not the grandchild victim). */
  void set_root_pid(__u32 p) { info_.root_pid = p; }
  /* The pid target::spawn() forked directly. For single-process targets this
   * equals info.pid; for nested targets this is the intermediate child (the
   * subtree root), while info.pid is its grandchild. */
  __u32 spawned_pid() const { return static_cast<__u32>(child_pid_); }
  /* FLAG <value> line captured by stop(); empty until stop() has been called.
   * Used to verify writev-style attacks actually mutated the target's buffer. */
  const std::string &observed_flag() const { return observed_flag_; }
  void stop();
  /* Writes one byte to the child's stdin as a "go" signal. Used by factories
   * whose target_fn performs the attack AFTER the caller has had a chance to
   * open a session. The target_fn must call getchar() once before the attack
   * to synchronise on this byte. Calling release() before stop() is required;
   * stop() closes stdin (EOF) which is the second synchronisation point. */
  void release();

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
