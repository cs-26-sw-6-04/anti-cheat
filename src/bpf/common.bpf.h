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

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, __u32);
} protected_pids SEC(".maps");

#ifdef AC_DEBUG_BUILD
volatile __u32 ac_enabled[AC_ENF__COUNT] = {
    [AC_ENF_SELFPROTECT] = 1,
    [AC_ENF_MEMORY] = 1,
    [AC_ENF_PTRACE] = 1,
};
#else
volatile const __u32 ac_enabled[AC_ENF__COUNT] = {
    [AC_ENF_SELFPROTECT] = 1,
    [AC_ENF_MEMORY] = 1,
    [AC_ENF_PTRACE] = 1,
};
#endif

/* Loader burns its pid into rodata before skel__load(). Hostile root cannot
 * rewrite a loaded program's rodata. */
volatile const __u32 ac_self_pid = 0;

static __always_inline bool enf_active(__u32 id) {
  return ac_enabled[id] != 0;
}

static __always_inline __u32 cur_pid(void) {
  return bpf_get_current_pid_tgid() >> 32;
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
