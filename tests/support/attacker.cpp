/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: MIT
 */

#include "attacker.hpp"

#include <cerrno>
#include <system_error>

#include <sys/wait.h>
#include <unistd.h>

namespace ac {

static std::string read_all(int fd) {
  std::string s;
  char buf[256];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0)
    s.append(buf, static_cast<size_t>(n));
  return s;
}

attack_result run_attacker(const attacker_fn &fn, const target_info &info) {
  int out[2];
  int err[2];
  if (pipe(out) != 0)
    throw std::system_error(errno, std::generic_category(), "pipe");
  if (pipe(err) != 0) {
    close(out[0]);
    close(out[1]);
    throw std::system_error(errno, std::generic_category(), "pipe");
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(out[0]);
    close(out[1]);
    close(err[0]);
    close(err[1]);
    throw std::system_error(errno, std::generic_category(), "fork");
  }

  if (pid == 0) {
    dup2(out[1], STDOUT_FILENO);
    dup2(err[1], STDERR_FILENO);
    close(out[0]);
    close(out[1]);
    close(err[0]);
    close(err[1]);
    int rc = fn(info);
    _exit(rc & 0xff);
  }

  close(out[1]);
  close(err[1]);

  attack_result r{};
  r.stdout = read_all(out[0]);
  r.stderr = read_all(err[0]);
  close(out[0]);
  close(err[0]);

  int status = 0;
  waitpid(pid, &status, 0);
  if (WIFEXITED(status))
    r.exit_code = WEXITSTATUS(status);
  else if (WIFSIGNALED(status))
    r.exit_code = 128 + WTERMSIG(status);
  else
    r.exit_code = -1;
  return r;
}

} // namespace ac
