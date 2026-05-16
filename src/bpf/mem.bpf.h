/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include "common.bpf.h"

SEC("lsm/ptrace_access_check")
int BPF_PROG(mem_enforce, struct task_struct *child, unsigned int mode,
             int ret) {
  if (ret)
    return ret;

  __u32 me = cur_pid();
  __u32 victim = BPF_CORE_READ(child, tgid);
  if (me == victim)
    return 0;

  if (!is_in_protected_subtree(child))
    return 0;

  /* Subtree is one trust domain: the §3.1 memory-confidentiality property
   * is about *external* attackers, so descendant->descendant traffic is
   * out of scope. Minecraft's own JVM threads otherwise fire this hook 600+
   * times per launch reading their siblings' /proc/<pid>/maps. */
  if (is_in_protected_subtree(bpf_get_current_task_btf()))
    return 0;

  emit_deny(AC_ENF_MEMORY, me, victim);
  return -EPERM;
}
