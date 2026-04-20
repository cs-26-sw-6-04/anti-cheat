/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include "common.bpf.h"

SEC("lsm/ptrace_access_check")
int BPF_PROG(selfprotect, struct task_struct *child, unsigned int mode,
             int ret) {
  if (ret)
    return ret;
  if (!enf_active(AC_ENF_SELFPROTECT))
    return 0;

  __u32 victim = BPF_CORE_READ(child, tgid);
  if (victim != ac_self_pid)
    return 0;

  __u32 me = cur_pid();
  if (me == ac_self_pid)
    return 0;

  emit_deny(AC_ENF_SELFPROTECT, me, victim);
  return -EPERM;
}
