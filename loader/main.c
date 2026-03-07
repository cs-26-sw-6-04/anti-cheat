/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>

#include "bpf-skeleton.h"
#include "hello_world.h"
#include <bpf/libbpf.h>

static volatile int running = 1;

static void on_signal(int sig) {
  (void)sig;
  running = 0;
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt,
                        va_list args) {
  if (level == LIBBPF_DEBUG)
    return 0;
  return vfprintf(stderr, fmt, args);
}

static int on_event(void *ctx, void *data, size_t sz) {
  (void)ctx;
  (void)sz;
  const struct event *e = data;
  printf("execve pid=%-6u uid=%-6u comm=%s\n", e->pid, e->uid, e->comm);
  return 0;
}

int main(void) {
  struct combined_bpf_lib *skel;
  struct ring_buffer *rb;
  int err;

  libbpf_set_print(libbpf_print);
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);

  skel = combined_bpf_lib__open_and_load();
  if (!skel) {
    fprintf(stderr, "failed to open/load skeleton\n");
    return 1;
  }

  err = combined_bpf_lib__attach(skel);
  if (err) {
    fprintf(stderr, "failed to attach: %d\n", err);
    goto out;
  }

  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), on_event, NULL, NULL);
  if (!rb) {
    err = -errno;
    fprintf(stderr, "failed to create ring buffer: %d\n", err);
    goto out;
  }

  printf("watching execve, Ctrl-C to stop\n");

  while (running) {
    err = ring_buffer__poll(rb, 100);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      fprintf(stderr, "poll error: %d\n", err);
      break;
    }
  }

  ring_buffer__free(rb);
out:
  combined_bpf_lib__destroy(skel);
  return err < 0 ? -err : 0;
}
