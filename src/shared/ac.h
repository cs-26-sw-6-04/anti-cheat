/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AC_FLAG_SIZE 64

/* Upper bound on task->real_parent walks from the victim during enforcement.
 * Higher than any realistic process tree depth; hitting it means either a
 * pathological tree or a hostile nesting attempt to escape protection. */
#define AC_ANCESTOR_WALK_DEPTH 64

enum ac_enforcer {
  AC_ENF_SELFPROTECT = 1,
  /* Subtree access enforcer: blocks any process_vm_{read,write}v, ptrace,
   * and /proc/PID/mem access where the victim is in the protected subtree.
   *
   * There is no AC_ENF_PTRACE. The `ptrace_access_check` LSM hook receives
   * the same mode bits for process_vm_rw and ptrace(PTRACE_ATTACH), so a
   * reliable attribution split is not possible at this layer. See
   * docs/testing.md. */
  AC_ENF_MEMORY = 2,
  AC_ENF__COUNT = 3,
};

enum ac_event_kind {
  AC_EVENT_DENY = 1,
};

struct ac_event {
  __u32 kind;
  __u32 enforcer;
  __u32 pid;
  __u32 target_pid;
  __s32 denied_errno;
};

struct ac_session;

/* Open an enforcement session.
 *
 * `protected_root_pid` declares the subtree the memory/ptrace enforcers guard.
 * The caller must already have spawned the protected root and must be its
 * parent; the pid is burned into BPF rodata at skeleton load so hostile root
 * cannot shift enforcement onto a different target after attach. Pass 0 to
 * run with selfprotect only (no subtree enforcement) — useful for tests and
 * diagnostic sessions.
 *
 * To eliminate the spawn→attach race, the caller should hold the protected
 * root stopped (SIGSTOP, ptrace, or a startup barrier) across this call and
 * resume it only after ac_open returns 0. To bind the protected root's life
 * to the loader's (see SCOPE.md, "Residual Weaknesses"), the protected root
 * should call prctl(PR_SET_PDEATHSIG, SIGKILL) on itself before ac_open, and
 * the loader should set PR_SET_CHILD_SUBREAPER so reparented descendants
 * remain in the loader's subtree. */
int ac_open(struct ac_session **out, __u32 protected_root_pid);
void ac_close(struct ac_session *session);

int ac_poll(struct ac_session *session, int timeout_ms);
int ac_next_event(struct ac_session *session, struct ac_event *out);

#ifdef AC_DEBUG_BUILD
int ac_set_enforcer_enabled(struct ac_session *session, enum ac_enforcer id,
                            int on);
#endif

#ifdef __cplusplus
}
#endif
