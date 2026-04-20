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

enum ac_enforcer {
  AC_ENF_SELFPROTECT = 1,
  AC_ENF_MEMORY = 2,
  AC_ENF_PTRACE = 3,
  AC_ENF__COUNT = 4,
};

enum ac_policy {
  AC_POLICY_BLOCK_MEMORY = 1u << 0,
  AC_POLICY_BLOCK_PTRACE = 1u << 1,
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

int ac_open(struct ac_session **out);
void ac_close(struct ac_session *session);

int ac_protect(struct ac_session *session, __u32 pid, __u32 policy);
int ac_unprotect(struct ac_session *session, __u32 pid);

int ac_poll(struct ac_session *session, int timeout_ms);
int ac_next_event(struct ac_session *session, struct ac_event *out);

#ifdef AC_DEBUG_BUILD
int ac_set_enforcer_enabled(struct ac_session *session, enum ac_enforcer id,
                            int on);
#endif

#ifdef __cplusplus
}
#endif
