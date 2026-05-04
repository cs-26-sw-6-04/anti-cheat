/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "ac.h"
#include "session.h"

#include "enforcers_bpf.skel.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static int libbpf_print(enum libbpf_print_level level, const char *fmt,
                        va_list args) {
  if (level == LIBBPF_DEBUG)
    return 0;
  return vfprintf(stderr, fmt, args);
}

/* Our enforcers are SEC("lsm/..."). The kernel happily loads and attaches
 * them even when BPF LSM is compiled in but not in the active lsm= stack;
 * the hooks then never run and every attack silently succeeds. Fail loudly
 * instead of pretending to protect. */
static int require_bpf_lsm_active(void) {
  FILE *f = fopen("/sys/kernel/security/lsm", "re");
  if (!f) {
    fprintf(stderr,
            "ac: cannot open /sys/kernel/security/lsm (%s); BPF LSM status "
            "unknown — refusing to attach silently.\n",
            strerror(errno));
    return -EOPNOTSUPP;
  }
  char buf[512] = {0};
  size_t n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = '\0';

  for (char *tok = strtok(buf, ",\n"); tok; tok = strtok(NULL, ",\n")) {
    if (strcmp(tok, "bpf") == 0)
      return 0;
  }
  fprintf(stderr,
          "ac: BPF LSM is not in the active LSM stack. Enforcers would load "
          "but never run. Boot with lsm=...,bpf (e.g. append to GRUB_CMDLINE) "
          "and reboot.\n");
  return -EOPNOTSUPP;
}

static int on_event(void *ctx, void *data, size_t size) {
  struct ac_session *s = ctx;
  if (size != sizeof(struct ac_event))
    return 0;
  if (s->has_next)
    return -ENOSPC;
  s->next = *(const struct ac_event *)data;
  s->has_next = 1;
  return 0;
}

int ac_open(struct ac_session **out, __u32 protected_root_pid) {
  if (!out)
    return -EINVAL;
  /* Loader is its own selfprotect domain; protecting it as the subtree root
   * collides with selfprotect on the same victim and breaks attribution. The
   * caller almost certainly meant to pass a child's pid. */
  if (protected_root_pid != 0 && protected_root_pid == (__u32)getpid())
    return -EINVAL;

  libbpf_set_print(libbpf_print);

  int lsm_err = require_bpf_lsm_active();
  if (lsm_err)
    return lsm_err;

  struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
  (void)setrlimit(RLIMIT_MEMLOCK, &rl);

  struct ac_session *s = calloc(1, sizeof(*s));
  if (!s)
    return -ENOMEM;

  s->skel = enforcers_bpf__open();
  if (!s->skel) {
    free(s);
    return -errno ? -errno : -EIO;
  }

  /* Burn both pids into rodata before load. rodata of a loaded program is
   * immutable from userspace — hostile root cannot redirect enforcement onto
   * a different self/target after the fact, which is the entire reason the
   * protected set lives here instead of in a mutable map. */
  s->skel->rodata->ac_self_pid = (__u32)getpid();
  s->skel->rodata->ac_protected_root_pid = protected_root_pid;

  int err = enforcers_bpf__load(s->skel);
  if (err)
    goto fail;

  err = enforcers_bpf__attach(s->skel);
  if (err)
    goto fail;

  s->events = ring_buffer__new(bpf_map__fd(s->skel->maps.events), on_event, s,
                               NULL);
  if (!s->events) {
    err = -errno ? -errno : -EIO;
    goto fail;
  }

  *out = s;
  return 0;

fail:
  enforcers_bpf__destroy(s->skel);
  free(s);
  return err < 0 ? err : -err;
}

void ac_close(struct ac_session *s) {
  if (!s)
    return;
  if (s->events)
    ring_buffer__free(s->events);
  if (s->skel)
    enforcers_bpf__destroy(s->skel);
  free(s);
}

int ac_poll(struct ac_session *s, int timeout_ms) {
  if (!s)
    return -EINVAL;
  return ring_buffer__poll(s->events, timeout_ms);
}

int ac_next_event(struct ac_session *s, struct ac_event *out) {
  if (!s || !out)
    return -EINVAL;
  if (!s->has_next)
    return -EAGAIN;
  *out = s->next;
  s->has_next = 0;
  return 0;
}

int ac_spawn_and_protect(struct ac_session **out, __u32 *out_pid,
                         ac_protected_main_fn child_main, void *user_data) {
  if (!out || !child_main)
    return -EINVAL;

  /* Set subreaper before fork so the child (and any of its descendants that
   * outlive intermediate parents) is guaranteed to reparent into us, keeping
   * the BPF ancestor walk from escaping the subtree. Idempotent. */
  (void)prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

  int barrier[2];
  if (pipe(barrier) != 0)
    return errno ? -errno : -EIO;

  pid_t pid = fork();
  if (pid < 0) {
    int e = errno;
    close(barrier[0]);
    close(barrier[1]);
    return -e;
  }

  if (pid == 0) {
    /* Bind life to the loader BEFORE running anything else. If the loader is
     * already gone here, the kernel delivers SIGKILL on the next signal-check
     * boundary and we never reach child_main. */
    (void)prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    close(barrier[1]);

    /* Block until the parent finishes ac_open. A successful 1-byte read means
     * enforcement is live; EOF means attach failed and we exit cleanly. */
    char b;
    ssize_t r;
    do {
      r = read(barrier[0], &b, 1);
    } while (r < 0 && errno == EINTR);
    close(barrier[0]);
    if (r != 1)
      _exit(127);

    int rc = child_main(user_data);
    _exit(rc & 0xff);
  }

  /* Parent. */
  close(barrier[0]);

  int err = ac_open(out, (__u32)pid);
  if (err) {
    /* Closing the write end without a release byte gives the child EOF; it
     * exits 127 on the r != 1 path. Reap it so the caller never has to. */
    close(barrier[1]);
    int status;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return err;
  }

  /* Release the child. */
  ssize_t w;
  do {
    w = write(barrier[1], "x", 1);
  } while (w < 0 && errno == EINTR);
  int werr = (w == 1) ? 0 : (errno ? -errno : -EIO);
  close(barrier[1]);

  if (werr) {
    /* Child died between fork and release (e.g. PR_SET_PDEATHSIG fired) —
     * unwind cleanly so callers never see a half-built session. */
    ac_close(*out);
    *out = NULL;
    int status;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return werr;
  }

  if (out_pid)
    *out_pid = (__u32)pid;
  return 0;
}
