/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <cerrno>
#include <cstring>

#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "targets.hpp"

using namespace ac;

TEST_CASE("whitelisted caller bypasses memory enforcer", "[whitelist][mem]") {
  auto sess = session::open_or_skip();
  auto t = targets::flag_secret()();
  sess.protect(t.info().pid, AC_POLICY_BLOCK_MEMORY);

  int pipefd[2];
  REQUIRE(pipe(pipefd) == 0);

  pid_t attacker = fork();
  REQUIRE(attacker >= 0);

  if (attacker == 0) {
    /* Child: send own PID to parent, wait, then attempt process_vm_readv. */
    close(pipefd[0]);
    pid_t me = getpid();
    write(pipefd[1], &me, sizeof(me));
    close(pipefd[1]);

    usleep(200000); /* 200ms — parent whitelists us in this window */

    char buf[64] = {0};
    struct iovec local  = { buf,                          sizeof(buf) };
    struct iovec remote = { (void *)t.info().addr,
                            t.info().len < sizeof(buf) ? t.info().len : sizeof(buf) };
    int rc = process_vm_readv(t.info().pid, &local, 1, &remote, 1, 0);
    _exit(rc >= 0 ? 0 : 1);
  }

  /* Parent: read attacker PID, whitelist it, then collect result. */
  close(pipefd[1]);
  pid_t attacker_pid = 0;
  read(pipefd[0], &attacker_pid, sizeof(attacker_pid));
  close(pipefd[0]);

  sess.whitelist((__u32)attacker_pid);

  int status = 0;
  waitpid(attacker, &status, 0);
  int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

  sess.drain();
  auto ev = sess.next_event();

  REQUIRE(exit_code == 0);         /* attack succeeded (whitelisted) */
  REQUIRE_FALSE(ev.has_value());   /* no deny event emitted */

  t.stop();
}

TEST_CASE("whitelisted caller bypasses ptrace enforcer", "[whitelist][ptrace]") {
  auto sess = session::open_or_skip();
  auto t = targets::flag_secret()();
  sess.protect(t.info().pid, AC_POLICY_BLOCK_PTRACE);

  int pipefd[2];
  REQUIRE(pipe(pipefd) == 0);

  pid_t attacker = fork();
  REQUIRE(attacker >= 0);

  if (attacker == 0) {
    close(pipefd[0]);
    pid_t me = getpid();
    write(pipefd[1], &me, sizeof(me));
    close(pipefd[1]);

    usleep(200000);

    long rc = ptrace(PTRACE_ATTACH, t.info().pid, 0, 0);
    if (rc == 0) {
      waitpid(t.info().pid, nullptr, 0);
      ptrace(PTRACE_DETACH, t.info().pid, 0, 0);
    }
    _exit(rc == 0 ? 0 : 1);
  }

  close(pipefd[1]);
  pid_t attacker_pid = 0;
  read(pipefd[0], &attacker_pid, sizeof(attacker_pid));
  close(pipefd[0]);

  sess.whitelist((__u32)attacker_pid);

  int status = 0;
  waitpid(attacker, &status, 0);
  int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

  sess.drain();
  auto ev = sess.next_event();

  REQUIRE(exit_code == 0);
  REQUIRE_FALSE(ev.has_value());

  t.stop();
}

TEST_CASE("selfprotect is NOT bypassed by whitelist", "[whitelist][selfprotect]") {
  /* Even if the attacker PID is in whitelist_pids, selfprotect must still fire
   * when the victim is the AC loader's own PID (ac_self_pid rodata constant). */
  auto sess = session::open_or_skip();
  auto t = targets::ac_self()();

  int pipefd[2];
  REQUIRE(pipe(pipefd) == 0);

  pid_t attacker = fork();
  REQUIRE(attacker >= 0);

  if (attacker == 0) {
    close(pipefd[0]);
    pid_t me = getpid();
    write(pipefd[1], &me, sizeof(me));
    close(pipefd[1]);

    usleep(200000);

    char buf[64] = {0};
    struct iovec local  = { buf,                          sizeof(buf) };
    struct iovec remote = { (void *)t.info().addr,
                            t.info().len < sizeof(buf) ? t.info().len : sizeof(buf) };
    int rc = process_vm_readv(t.info().pid, &local, 1, &remote, 1, 0);
    _exit(rc >= 0 ? 0 : 1);
  }

  close(pipefd[1]);
  pid_t attacker_pid = 0;
  read(pipefd[0], &attacker_pid, sizeof(attacker_pid));
  close(pipefd[0]);

  /* Whitelist the attacker — selfprotect must STILL block it. */
  sess.whitelist((__u32)attacker_pid);

  int status = 0;
  waitpid(attacker, &status, 0);
  int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

  sess.poll(500);
  auto ev = sess.next_event();

  REQUIRE(exit_code != 0);         /* attack blocked */
  REQUIRE(ev.has_value());         /* deny event emitted */
  REQUIRE(ev->enforcer == static_cast<__u32>(AC_ENF_SELFPROTECT));

  t.stop();
}
