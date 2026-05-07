/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <cerrno>

#include <signal.h>
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
