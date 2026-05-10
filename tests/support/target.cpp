/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "target.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ac {

target::~target() { terminate(); }

target::target(target &&o) noexcept { *this = std::move(o); }

target &target::operator=(target &&o) noexcept {
  if (this != &o) {
    terminate();
    info_ = std::move(o.info_);
    observed_flag_ = std::move(o.observed_flag_);
    child_pid_ = o.child_pid_;
    stdin_fd_ = o.stdin_fd_;
    stdout_ = o.stdout_;
    stopped_ = o.stopped_;
    o.child_pid_ = 0;
    o.stdin_fd_ = -1;
    o.stdout_ = nullptr;
    o.stopped_ = true;
  }
  return *this;
}

target target::spawn(target_fn fn) {
  int in_pipe[2];
  int out_pipe[2];
  if (pipe(in_pipe) != 0)
    throw std::system_error(errno, std::generic_category(), "pipe");
  if (pipe(out_pipe) != 0) {
    close(in_pipe[0]);
    close(in_pipe[1]);
    throw std::system_error(errno, std::generic_category(), "pipe");
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(in_pipe[0]);
    close(in_pipe[1]);
    close(out_pipe[0]);
    close(out_pipe[1]);
    throw std::system_error(errno, std::generic_category(), "fork");
  }

  if (pid == 0) {
    /* Bind our lifetime to the test harness (which is the loader in these
     * tests). See SCOPE.md "Residual Weaknesses": loader death drops BPF
     * enforcement, so the protected subtree must die with it. */
    (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    dup2(in_pipe[0], STDIN_FILENO);
    dup2(out_pipe[1], STDOUT_FILENO);
    close(in_pipe[0]);
    close(in_pipe[1]);
    close(out_pipe[0]);
    close(out_pipe[1]);
    int rc = fn();
    _exit(rc);
  }

  close(in_pipe[0]);
  close(out_pipe[1]);

  target t;
  t.child_pid_ = pid;
  t.stdin_fd_ = in_pipe[1];
  t.stdout_ = fdopen(out_pipe[0], "r");
  if (!t.stdout_) {
    close(in_pipe[1]);
    close(out_pipe[0]);
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
    throw std::runtime_error("fdopen failed");
  }

  char line[256];
  if (!fgets(line, sizeof(line), t.stdout_))
    throw std::runtime_error("target did not print READY");

  unsigned int parsed_pid = 0;
  unsigned long long addr = 0;
  size_t len = 0;
  if (sscanf(line, "READY %u %llx %zu", &parsed_pid, &addr, &len) != 3)
    throw std::runtime_error("target READY malformed: " + std::string(line));

  t.info_.pid = parsed_pid;
  t.info_.addr = static_cast<uintptr_t>(addr);
  t.info_.len = len;
  return t;
}

target target::existing(__u32 pid, uintptr_t addr, size_t len) {
  target t;
  t.info_.pid = pid;
  t.info_.addr = addr;
  t.info_.len = len;
  t.stopped_ = true;
  return t;
}

void target::release() {
  if (stdin_fd_ >= 0) {
    /* Write a single arbitrary byte as the "go" signal.
     * The child's getchar() call before the attack reads this byte. */
    char go = '\n';
    ssize_t n = write(stdin_fd_, &go, 1);
    if (n != 1) {
      /* Child already died or pipe broken; stop() will reap it. */
      close(stdin_fd_);
      stdin_fd_ = -1;
    }
  }
}

void target::stop() {
  if (stopped_ || child_pid_ == 0)
    return;

  if (stdin_fd_ >= 0) {
    close(stdin_fd_);
    stdin_fd_ = -1;
  }

  char line[256];
  if (stdout_ && fgets(line, sizeof(line), stdout_)) {
    if (std::strncmp(line, "FLAG ", 5) == 0) {
      observed_flag_ = line + 5;
      if (!observed_flag_.empty() && observed_flag_.back() == '\n')
        observed_flag_.pop_back();
    }
  }

  int status = 0;
  if (waitpid(child_pid_, &status, WNOHANG) == 0) {
    kill(child_pid_, SIGTERM);
    waitpid(child_pid_, &status, 0);
  }

  if (stdout_) {
    fclose(stdout_);
    stdout_ = nullptr;
  }
  stopped_ = true;
}

void target::terminate() {
  if (stopped_ || child_pid_ == 0)
    return;
  if (stdin_fd_ >= 0)
    close(stdin_fd_);
  if (stdout_)
    fclose(stdout_);
  kill(child_pid_, SIGKILL);
  waitpid(child_pid_, nullptr, 0);
  stdin_fd_ = -1;
  stdout_ = nullptr;
  stopped_ = true;
}

} // namespace ac
