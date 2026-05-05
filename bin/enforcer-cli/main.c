/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * enforcer-cli — CLI wrapper around ac_loader_runtime.
 *
 * Usage: sudo enforcer-cli <target-pid> [--whitelist <pid1>[,<pid2>,...]]
 *
 * Opens a BPF LSM session, protects the target PID with full policy,
 * optionally whitelists one or more caller PIDs, then polls for deny events
 * and prints each one until SIGINT or SIGTERM.
 */

#include "ac.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void handle_stop(int sig) {
  (void)sig;
  g_stop = 1;
}

static const char *enforcer_name(__u32 e) {
  switch (e) {
  case AC_ENF_SELFPROTECT: return "SELFPROTECT";
  case AC_ENF_MEMORY:      return "MEMORY";
  case AC_ENF_PTRACE:      return "PTRACE";
  default:                 return "UNKNOWN";
  }
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <target-pid> [--whitelist <pid,...>]\n",
            argv[0]);
    return 1;
  }

  char *endptr = NULL;
  unsigned long target_ul = strtoul(argv[1], &endptr, 10);
  if (!endptr || *endptr != '\0' || target_ul == 0 || target_ul > UINT32_MAX) {
    fprintf(stderr, "error: invalid target PID: %s\n", argv[1]);
    return 1;
  }
  __u32 target_pid = (__u32)target_ul;

  /* Collect optional --whitelist PIDs before opening the session. */
  char *whitelist_arg = NULL;

  static const struct option long_opts[] = {
      {"whitelist", required_argument, NULL, 'w'},
      {NULL, 0, NULL, 0},
  };

  int opt;
  /* Reset getopt state; skip argv[1] which is the target PID. */
  optind = 2;
  while ((opt = getopt_long(argc, argv, "w:", long_opts, NULL)) != -1) {
    switch (opt) {
    case 'w':
      whitelist_arg = optarg;
      break;
    default:
      fprintf(stderr, "usage: %s <target-pid> [--whitelist <pid,...>]\n",
              argv[0]);
      return 1;
    }
  }

  /* Install signal handlers before attaching BPF programs. */
  struct sigaction sa = {0};
  sa.sa_handler = handle_stop;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  if (sigaction(SIGINT, &sa, NULL) != 0 ||
      sigaction(SIGTERM, &sa, NULL) != 0) {
    perror("sigaction");
    return 1;
  }

  struct ac_session *session = NULL;
  int err = ac_open(&session);
  if (err) {
    fprintf(stderr, "error: ac_open: %s\n", strerror(-err));
    return 1;
  }

  /* Protect the target PID with full policy. */
  err = ac_protect(session, target_pid,
                   AC_POLICY_BLOCK_MEMORY | AC_POLICY_BLOCK_PTRACE);
  if (err) {
    fprintf(stderr, "error: ac_protect(%u): %s\n", target_pid, strerror(-err));
    ac_close(session);
    return 1;
  }
  fprintf(stderr, "protecting pid %u\n", target_pid);

  /* Populate whitelist map before polling begins. */
  if (whitelist_arg) {
    char *copy = strdup(whitelist_arg);
    if (!copy) {
      perror("strdup");
      ac_close(session);
      return 1;
    }
    char *tok = strtok(copy, ",");
    while (tok) {
      char *ep = NULL;
      unsigned long wl_ul = strtoul(tok, &ep, 10);
      if (!ep || *ep != '\0' || wl_ul == 0 || wl_ul > UINT32_MAX) {
        fprintf(stderr, "warning: skipping invalid whitelist PID: %s\n", tok);
      } else {
        __u32 wl_pid = (__u32)wl_ul;
        int werr = ac_whitelist_add(session, wl_pid);
        if (werr)
          fprintf(stderr, "warning: ac_whitelist_add(%u): %s\n", wl_pid,
                  strerror(-werr));
        else
          fprintf(stderr, "whitelisted pid %u\n", wl_pid);
      }
      tok = strtok(NULL, ",");
    }
    free(copy);
  }

  fprintf(stderr, "monitoring — press Ctrl-C to stop\n");

  while (!g_stop) {
    int n = ac_poll(session, 500);
    if (n < 0 && n != -EINTR) {
      fprintf(stderr, "error: ac_poll: %s\n", strerror(-n));
      break;
    }
    struct ac_event ev;
    while (ac_next_event(session, &ev) == 0) {
      printf("DENY enforcer=%s attacker=%u victim=%u errno=%d\n",
             enforcer_name(ev.enforcer), ev.pid, ev.target_pid,
             ev.denied_errno);
      fflush(stdout);
    }
  }

  ac_close(session);
  return 0;
}
