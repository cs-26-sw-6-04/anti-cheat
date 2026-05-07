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
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* glibc only exposes pidfd_open from 2.36+; go through syscall(2) so we work
 * on older runtimes the kernel still supports. __NR_pidfd_open landed in
 * 5.3, well below our baseline. */
static int pidfd_open_compat(__u32 pid) {
  long fd = syscall(__NR_pidfd_open, (pid_t)pid, 0u);
  if (fd < 0)
    return -errno;
  return (int)fd;
}

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
            "unknown; refusing to attach silently.\n",
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
  s->root_pidfd = -1;

  /* Bind to the protected root's task_struct *before* we burn its pid into
   * rodata. If the root is already gone, fail fast with -ESRCH and never
   * load BPF programs that would protect a stranger after pid reuse. */
  if (protected_root_pid != 0) {
    int pidfd = pidfd_open_compat(protected_root_pid);
    if (pidfd < 0) {
      free(s);
      return pidfd;
    }
    s->root_pidfd = pidfd;
  }

  s->skel = enforcers_bpf__open();
  if (!s->skel) {
    int e = errno ? -errno : -EIO;
    if (s->root_pidfd >= 0)
      close(s->root_pidfd);
    free(s);
    return e;
  }

  /* Burn both pids into rodata before load. rodata of a loaded program is
   * immutable from userspace, so hostile root cannot redirect enforcement
   * onto a different self/target after the fact, which is the entire reason
   * the protected set lives here instead of in a mutable map. */
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
  if (s->root_pidfd >= 0)
    close(s->root_pidfd);
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
  if (s->root_pidfd >= 0)
    close(s->root_pidfd);
  free(s);
}

/* Tear down BPF enforcement immediately on root death. Leaving programs
 * attached after the protected root exits would let a process awarded the
 * reused pid inherit protection, so we drop enforcement at the moment our
 * trust assumption breaks, not at the moment the caller gets around to
 * calling ac_close. The session struct itself stays alive so queued events
 * remain readable via ac_next_event. */
static void ac_tear_down_after_root_death(struct ac_session *s) {
  if (s->events) {
    ring_buffer__free(s->events);
    s->events = NULL;
  }
  if (s->skel) {
    enforcers_bpf__destroy(s->skel);
    s->skel = NULL;
  }
  if (s->root_pidfd >= 0) {
    close(s->root_pidfd);
    s->root_pidfd = -1;
  }
  s->root_dead = 1;
}

int ac_whitelist_add(struct ac_session *s, __u32 pid) {
  if (!s)
    return -EINVAL;
  __u32 marker = 1;
  return bpf_map__update_elem(s->skel->maps.whitelist_pids, &pid, sizeof(pid),
                              &marker, sizeof(marker), BPF_ANY);
}

int ac_whitelist_remove(struct ac_session *s, __u32 pid) {
  if (!s)
    return -EINVAL;
  int err = bpf_map__delete_elem(s->skel->maps.whitelist_pids, &pid,
                                 sizeof(pid), 0);
  if (err == -ENOENT)
    return 0;
  return err;
}

int ac_poll(struct ac_session *s, int timeout_ms) {
  if (!s)
    return -EINVAL;
  if (s->root_dead)
    return -ESRCH;

  /* No protected root: just drive the ring buffer. */
  if (s->root_pidfd < 0)
    return ring_buffer__poll(s->events, timeout_ms);

  struct pollfd pfds[2];
  pfds[0].fd = ring_buffer__epoll_fd(s->events);
  pfds[0].events = POLLIN;
  pfds[0].revents = 0;
  pfds[1].fd = s->root_pidfd;
  pfds[1].events = POLLIN;
  pfds[1].revents = 0;

  int rc = poll(pfds, 2, timeout_ms);
  if (rc < 0)
    return -errno;
  if (rc == 0)
    return 0;

  /* Drain any queued events first so the caller sees the final deny that
   * may have fired in the same instant the root died. */
  int events = 0;
  if (pfds[0].revents & POLLIN) {
    int n = ring_buffer__consume(s->events);
    if (n > 0)
      events = n;
  }

  if (pfds[1].revents & POLLIN) {
    ac_tear_down_after_root_death(s);
    return -ESRCH;
  }

  return events;
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
    /* Child died between fork and release (e.g. PR_SET_PDEATHSIG fired);
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
