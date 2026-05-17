/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <cerrno>

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.h"

TEST_CASE("ac_open rejects loader pid as protected_root_pid",
          "[api][negative]") {
  ac_session *s = nullptr;
  int err = ac_open(&s, (__u32)getpid());
  REQUIRE(err == -EINVAL);
  REQUIRE(s == nullptr);
}

namespace {
struct spawn_ud {
  int signal_fd;
};
} // namespace

TEST_CASE("ac_spawn_and_protect runs the child only after enforcement is live",
          "[api][spawn]") {
  /* The child writes a token to this pipe as its first action. If the byte
   * arrives, the barrier was released, which can only happen after ac_open
   * succeeded, so we've actually exercised the post-attach release. */
  int sig[2];
  REQUIRE(pipe(sig) == 0);

  spawn_ud ud{sig[1]};

  ac_session *s = nullptr;
  __u32 pid = 0;
  int err = ac_spawn_and_protect(
      &s, &pid,
      [](void *user) -> int {
        auto *u = static_cast<spawn_ud *>(user);
        char b = 'X';
        (void)write(u->signal_fd, &b, 1);
        close(u->signal_fd);
        pause();
        return 0;
      },
      &ud);

  /* Loader-side write end is no longer ours. */
  close(sig[1]);

  if (err == -EPERM || err == -EACCES) {
    close(sig[0]);
    SKIP("skipping live BPF test: insufficient privileges");
  }
  REQUIRE(err == 0);
  REQUIRE(s != nullptr);
  REQUIRE(pid != 0);

  char b = 0;
  REQUIRE(read(sig[0], &b, 1) == 1);
  REQUIRE(b == 'X');
  close(sig[0]);

  ac_close(s);
  REQUIRE(kill((pid_t)pid, SIGTERM) == 0);
  int status;
  (void)waitpid((pid_t)pid, &status, 0);
}

TEST_CASE("ac_poll returns -ESRCH after the protected root dies",
          "[api][pidfd]") {
  ac_session *s = nullptr;
  __u32 pid = 0;
  int err = ac_spawn_and_protect(
      &s, &pid, [](void *) -> int { pause(); return 0; }, nullptr);
  if (err == -EPERM || err == -EACCES) {
    SKIP("skipping live BPF test: insufficient privileges");
  }
  REQUIRE(err == 0);
  REQUIRE(pid != 0);

  /* Healthy session: short poll returns 0 (no events, root alive). */
  REQUIRE(ac_poll(s, 50) == 0);

  REQUIRE(kill((pid_t)pid, SIGKILL) == 0);

  /* Drive the poll loop until pidfd notifies us. Even with SIGKILL the
   * notification is async w.r.t. the killer; one or two iterations suffice
   * in practice. */
  int rc = 0;
  for (int i = 0; i < 20; i++) {
    rc = ac_poll(s, 100);
    if (rc == -ESRCH)
      break;
  }
  REQUIRE(rc == -ESRCH);

  /* Sticky: subsequent polls keep returning -ESRCH. */
  REQUIRE(ac_poll(s, 10) == -ESRCH);

  ac_close(s);
  int status;
  (void)waitpid((pid_t)pid, &status, 0);
}

TEST_CASE("loader death kills protected root across cred drop",
          "[api][lifetime][pdeathsig]") {
  /* Reproduces the cli's setuid-root path. The loader proxy sets real uid
   * to nobody but keeps effective root for ac_open's BPF privilege; that
   * way libloader's setuid(getuid()) inside the spawned child performs a
   * real fsuid change. That is the path that clears task->pdeath_signal
   * in commit_creds(), and is what broke before the
   * pdeathsig-after-setuid fix. The test asserts that killing the loader
   * still kills the protected root: failure here means setuid silently
   * destroyed pdeathsig because it was armed before the cred change.
   *
   * When the test runner is itself just root (real == effective == 0),
   * libloader's setuid(getuid()) is a no-op and the kernel does not run
   * the fsuid-change path, so this test would not exercise the bug-prone
   * window. Forcing real != effective here is the whole point. */

  if (geteuid() != 0) {
    SKIP("requires root (BPF load + setresuid)");
  }

  int pid_pipe[2];
  REQUIRE(pipe(pid_pipe) == 0);

  pid_t loader = fork();
  REQUIRE(loader >= 0);

  if (loader == 0) {
    close(pid_pipe[0]);
    /* Make real uid != effective uid without dropping caps: euid stays 0,
     * so commit_creds() does not change fsuid here and we keep CAP_BPF /
     * CAP_SYS_ADMIN to load programs. The libloader's setuid(getuid()) in
     * the spawned grandchild will then drop euid 0 -> 65534 and trigger
     * the fsuid-change codepath we want to exercise. */
    if (setresuid(/*ruid=*/65534, /*euid=*/0, /*suid=*/0) != 0)
      _exit(70);

    ac_session *s = nullptr;
    __u32 pid = 0;
    int err = ac_spawn_and_protect(
        &s, &pid, [](void *) -> int { pause(); return 0; }, nullptr);

    if (err != 0) {
      __u32 zero = 0;
      (void)write(pid_pipe[1], &zero, sizeof zero);
      _exit(err == -EPERM || err == -EACCES ? 77 : 1);
    }
    (void)write(pid_pipe[1], &pid, sizeof pid);
    close(pid_pipe[1]);
    pause();
    _exit(0);
  }

  close(pid_pipe[1]);

  __u32 protected_pid = 0;
  ssize_t r = read(pid_pipe[0], &protected_pid, sizeof protected_pid);
  close(pid_pipe[0]);
  REQUIRE(r == (ssize_t)sizeof protected_pid);

  if (protected_pid == 0) {
    int s_status = 0;
    (void)waitpid(loader, &s_status, 0);
    if (WIFEXITED(s_status) && WEXITSTATUS(s_status) == 77)
      SKIP("insufficient privileges to load BPF");
    FAIL("loader proxy failed before reporting protected pid");
  }

  /* Sanity: protected child is alive before we touch the loader. */
  REQUIRE(kill((pid_t)protected_pid, 0) == 0);

  /* Take the loader out from under it. PR_SET_PDEATHSIG(SIGKILL) on the
   * protected child must fire and take it out as well. */
  REQUIRE(kill(loader, SIGKILL) == 0);
  int loader_status = 0;
  (void)waitpid(loader, &loader_status, 0);

  /* We are not the protected child's parent, so wait by polling: kill(2)
   * with sig 0 returns -ESRCH once the pid is fully gone (zombie reaped
   * by the subreaper that inherited it). */
  bool dead = false;
  for (int i = 0; i < 200; i++) {
    if (kill((pid_t)protected_pid, 0) == -1 && errno == ESRCH) {
      dead = true;
      break;
    }
    usleep(10 * 1000); /* up to 2s total. */
  }
  REQUIRE(dead);
}
