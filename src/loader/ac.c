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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
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

int ac_open(struct ac_session **out) {
  if (!out)
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

  /* Burn self pid into rodata before load — verifier-observable constant. */
  s->skel->rodata->ac_self_pid = (__u32)getpid();

  int err = enforcers_bpf__load(s->skel);
  if (err)
    goto fail;

  err = enforcers_bpf__attach(s->skel);
  if (err)
    goto fail;

  __u32 self_pid = (__u32)getpid();
  __u32 self_policy = AC_POLICY_BLOCK_MEMORY | AC_POLICY_BLOCK_PTRACE;
  (void)bpf_map__update_elem(s->skel->maps.protected_pids, &self_pid,
                             sizeof(self_pid), &self_policy,
                             sizeof(self_policy), BPF_ANY);

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

int ac_protect(struct ac_session *s, __u32 pid, __u32 policy) {
  if (!s)
    return -EINVAL;
  return bpf_map__update_elem(s->skel->maps.protected_pids, &pid, sizeof(pid),
                              &policy, sizeof(policy), BPF_ANY);
}

int ac_unprotect(struct ac_session *s, __u32 pid) {
  if (!s)
    return -EINVAL;
  int err = bpf_map__delete_elem(s->skel->maps.protected_pids, &pid,
                                 sizeof(pid), 0);
  if (err == -ENOENT)
    return 0;
  return err;
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
