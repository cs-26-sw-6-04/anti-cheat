/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include "common.bpf.h"

SEC("lsm/bprm_check_security")
int BPF_PROG(execve_enforce, struct linux_binprm *bprm, int ret) {
  if (ret)
    return ret;

  __u32 me = cur_pid();

  /* The protected subtree root's own exec is its startup (the game binary
   * being exec'd after ac_spawn_and_protect releases the barrier). Allowing
   * the root to exec once is intentional and does not open a bypass: after
   * exec completes the root's address space is the game binary, not an
   * attacker binary, because ac_spawn_and_protect does not give the child
   * any control over which binary to exec (exec_child in tests uses /bin/true
   * as the malicious payload; real attackers would use an attacker binary).
   *
   * A descendant of the root that execs is not performing startup; it is
   * attempting to replace itself with a potentially malicious binary.
   * See design-decisions.md A2 for the rationale. */
  if (me == ac_protected_root_pid)
    return 0;

  struct task_struct *t = bpf_get_current_task_btf();

  if (!is_in_protected_subtree(t))
    return 0;

  /* Victim is the exec'ing process itself. We do not log bprm->file path
   * (privacy constraint: no filenames in events). */
  emit_deny(AC_ENF_EXECVE, me, me);
  return -EPERM;
}
