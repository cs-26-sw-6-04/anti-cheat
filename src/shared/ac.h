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
 * `protected_root_pid` declares the subtree the memory enforcer guards. The
 * caller must already have spawned the protected root and must be its parent;
 * the pid is burned into BPF rodata at skeleton load so hostile root cannot
 * shift enforcement onto a different target after attach. Pass 0 to run with
 * selfprotect only (no subtree enforcement); useful for tests and diagnostic
 * sessions. The caller's own pid is rejected (-EINVAL): selfprotect already
 * covers it, and registering it as the subtree root would collide attribution
 * between the two enforcers on the same victim.
 *
 * Most production callers should prefer `ac_spawn_and_protect`, which owns
 * the spawn → attach orchestration (PR_SET_PDEATHSIG, PR_SET_CHILD_SUBREAPER,
 * the startup barrier) instead of leaving each loader to reimplement the
 * sequence. Use ac_open directly only when you already hold a child stopped
 * by other means (e.g., ptrace) or you know the protected root has not yet
 * begun executing attackable code. */
int ac_open(struct ac_session **out, __u32 protected_root_pid);
void ac_close(struct ac_session *session);

typedef int (*ac_protected_main_fn)(void *user_data);

int ac_whitelist_add(struct ac_session *session, __u32 pid);
int ac_whitelist_remove(struct ac_session *session, __u32 pid);

/* Spawn a process running `child_main(user_data)` and attach BPF enforcement
 * with that process as the protected subtree root. Closes the spawn → attach
 * race via an internal pipe barrier: the child does not begin executing
 * `child_main` until the BPF programs are loaded and attached.
 *
 * Sequence the function performs on the caller's behalf, in order:
 *   1. PR_SET_CHILD_SUBREAPER on the loader so reparented descendants of the
 *      subtree stay reachable for the ancestor walk.
 *   2. fork().
 *   3. Child sets PR_SET_PDEATHSIG(SIGKILL) before doing anything else, so
 *      loader death tears the subtree down (see SCOPE.md "Residual
 *      Weaknesses").
 *   4. Child blocks on the barrier read.
 *   5. Parent calls ac_open with the child's pid as the subtree root.
 *   6. On success, parent releases the barrier; child runs `child_main`.
 *      On failure, parent closes the barrier write end (child gets EOF and
 *      exits) and reaps it before returning the error.
 *
 * On success `*out` is a live session, `*out_pid` (if non-null) receives the
 * protected root's pid, and the caller is responsible for `ac_close` and for
 * waiting on / signalling the child. On failure no session is left open and
 * no child is left orphaned. Return values match ac_open. */
int ac_spawn_and_protect(struct ac_session **out, __u32 *out_pid,
                         ac_protected_main_fn child_main, void *user_data);

/* Drive the ring buffer and watch the protected root for exit.
 *
 * Returns the number of events consumed (≥ 0), or a negative errno. The
 * specific errno -ESRCH means the protected root has died: the session has
 * already torn down its BPF state to avoid protecting whoever inherits the
 * pid, and queued events (if any) remain readable via ac_next_event. The
 * caller must call ac_close. Subsequent ac_poll calls keep returning -ESRCH
 * (sticky). Sessions opened with protected_root_pid == 0 never observe
 * -ESRCH. */
int ac_poll(struct ac_session *session, int timeout_ms);
int ac_next_event(struct ac_session *session, struct ac_event *out);

#ifdef __cplusplus
}
#endif
