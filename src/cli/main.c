/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "ac.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct exec_ctx {
  char **argv; /* NULL-terminated; argv[0] is the program. */
};

static int exec_child(void *user) {
  struct exec_ctx *c = user;

  /* Drop root before handing control to the user's program. setuid(ruid)
   * with euid == 0 sets all three (real, effective, saved) uids to ruid;
   * the program cannot regain root. We never elevated egid or groups
   * (no setgid bit, no setcap +s) so they already match the caller. */
  if (setuid(c->real_uid) != 0) {
    fprintf(stderr, "ac: setuid: %s\n", strerror(errno));
    return 126;
  }

  execvp(c->argv[0], c->argv);
  fprintf(stderr, "ac: exec '%s': %s\n", c->argv[0], strerror(errno));
  return 127;
}

static const char *enforcer_name(unsigned int id) {
  switch (id) {
  case AC_ENF_SELFPROTECT:
    return "selfprotect";
  case AC_ENF_MEMORY:
    return "memory";
  default:
    return "?";
  }
}

static void usage(const char *me) {
  fprintf(stderr,
          "usage: %s <command> [args...]\n"
          "\n"
          "Run <command> with anti-cheat protection. While it runs, other\n"
          "processes can't read or write its memory and can't attach a\n"
          "debugger to it. Anything that tries gets blocked, with a line\n"
          "printed to stderr.\n"
          "\n"
          "Examples:\n"
          "  %s ./mygame\n"
          "  %s /opt/games/mygame --windowed\n"
          "\n"
          "Your program runs as your normal user. ac itself needs to be\n"
          "setuid root once so it can install the kernel hooks; if it\n"
          "isn't, it'll print the one-time setup command.\n",
          me, me, me);
}

static void print_install_hint(const char *me) {
  fprintf(stderr,
          "ac: not setuid root, can't load kernel hooks.\n"
          "One-time setup:\n"
          "    sudo chown root:root %s\n"
          "    sudo chmod u+s %s\n"
          "After that, run as your normal user.\n",
          me, me);
}

int main(int argc, char **argv) {
  if (argc < 2 || strcmp(argv[1], "-h") == 0 ||
      strcmp(argv[1], "--help") == 0) {
    usage(argv[0]);
    return argc < 2 ? 2 : 0;
  }

  if (geteuid() != 0) {
    print_install_hint(argv[0]);
    return 1;
  }

  struct exec_ctx ctx = {.argv = &argv[1]};

  struct ac_session *s = NULL;
  __u32 pid = 0;
  int err = ac_spawn_and_protect(&s, &pid, exec_child, &ctx);
  if (err) {
    fprintf(stderr, "ac: spawn_and_protect: %s\n", strerror(-err));
    return 1;
  }

  for (;;) {
    int rc = ac_poll(s, 200);
    if (rc == -ESRCH)
      break; /* protected root has exited; collect status below. */
    if (rc < 0) {
      if (-rc == EINTR)
        continue;
      fprintf(stderr, "ac: poll: %s\n", strerror(-rc));
      break;
    }

    struct ac_event ev;
    while (ac_next_event(s, &ev) == 0) {
      fprintf(stderr, "ac: deny [%s] attacker=%u victim=%u errno=%d\n",
              enforcer_name(ev.enforcer), ev.pid, ev.target_pid,
              ev.denied_errno);
    }
  }

  ac_close(s);

  int status = 0;
  while (waitpid((pid_t)pid, &status, 0) < 0 && errno == EINTR) {
  }
  if (WIFEXITED(status))
    return WEXITSTATUS(status);
  if (WIFSIGNALED(status))
    return 128 + WTERMSIG(status);
  return 1;
}
