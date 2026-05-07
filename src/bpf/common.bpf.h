/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#include "ac.h"

#define AC_PTRACE_MODE_ATTACH 0x02

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Loader burns its own pid and the protected subtree root pid into rodata
 * before skel__load(). rodata of a loaded program is not writable from
 * userspace, so hostile root cannot redirect enforcement post-attach.
 *
 * There is intentionally no per-enforcer on/off bit. A central control
 * plane is a single point of bypass: flipping one byte (bitflip,
 * write-what-where in a kernel exploit, accidentally-deployed Debug
 * binary) would silently disable every enforcer that gates on it.
 * Selfprotect and memory are unconditional; they decide whether to fire
 * by looking at the victim's domain (ac_self_pid for selfprotect, the
 * subtree ancestry walk for memory). The two domains are disjoint by
 * topological construction (loader is the parent of the protected root,
 * not a descendant), so there is nothing for a runtime toggle to
 * arbitrate. */
volatile const __u32 ac_self_pid = 0;
volatile const __u32 ac_protected_root_pid = 0;

static __always_inline __u32 cur_pid(void) {
  return bpf_get_current_pid_tgid() >> 32;
}

/* True iff `child`'s tgid is ac_protected_root_pid or one of its descendants,
 * via a bounded real_parent walk. Selfprotect (victim == ac_self_pid) is a
 * disjoint domain and handled by its own program; this helper deliberately
 * does not treat ac_self_pid as protected so mem/ptrace attribution never
 * clashes with selfprotect's. Stops at init (tgid<=1) to avoid walking the
 * rest of the system. real_parent is kernel-owned bookkeeping that cannot
 * be altered from userspace without a kernel module (out of scope per
 * SCOPE.md's trusted base). */
static __always_inline bool is_in_protected_subtree(struct task_struct *t) {
  if (!ac_protected_root_pid)
    return false;

  struct task_struct *cur = t;
#pragma unroll
  for (int i = 0; i < AC_ANCESTOR_WALK_DEPTH; i++) {
    if (!cur)
      return false;
    __u32 tgid = BPF_CORE_READ(cur, tgid);
    if (tgid == ac_protected_root_pid)
      return true;
    if (tgid <= 1)
      return false;
    cur = BPF_CORE_READ(cur, real_parent);
  }
  return false;
}

static __always_inline void emit_deny(__u32 enforcer, __u32 attacker,
                                      __u32 victim) {
  struct ac_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return;
  e->kind = AC_EVENT_DENY;
  e->enforcer = enforcer;
  e->pid = attacker;
  e->target_pid = victim;
  e->denied_errno = -EPERM;
  bpf_ringbuf_submit(e, 0);
}
