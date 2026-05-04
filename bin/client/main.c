/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * client — game-process analog for the anti-cheat demo.
 *
 * Prints its PID on stdout, then loops sleeping until SIGINT or SIGTERM.
 * The PID printed on the first line is what the enforcer and attackers target.
 */

#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void handle_stop(int sig) {
  (void)sig;
  g_stop = 1;
}

int main(void) {
  struct sigaction sa = {0};
  sa.sa_handler = handle_stop;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if (sigaction(SIGINT, &sa, NULL) != 0 ||
      sigaction(SIGTERM, &sa, NULL) != 0) {
    perror("sigaction");
    return 1;
  }

  printf("%u\n", (unsigned)getpid());
  fflush(stdout);

  while (!g_stop) {
    sleep(1);
  }

  return 0;
}
