/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include "common.bpf.h"

SEC("lsm/mmap_file")
int BPF_PROG(inject_mmap_enforce, struct file *file,
             unsigned long reqprot, unsigned long prot,
             unsigned long flags, int ret) {
  if (ret)
    return ret;

  /* Only anonymous PROT_EXEC mappings are shellcode candidates.
   * File-backed mappings (file != NULL) are legitimate library loads by ld.so
   * and must not be blocked -- a game's own startup loads .so files this way.
   * The filter (file == NULL) is intentional: it means this enforcer ONLY
   * fires when the protected process allocates executable anonymous memory,
   * which has no legitimate use outside JIT runtimes (see design-decisions.md A1). */
  if (!(prot & PROT_EXEC))
    return 0;
  if (file != NULL)
    return 0;

  __u32 me = cur_pid();
  /* mmap_file does not supply a task_struct argument -- retrieve the caller's
   * task via bpf_get_current_task_btf() (requires kernel 5.11+, which is
   * the project minimum). */
  struct task_struct *t = bpf_get_current_task_btf();

  if (!is_in_protected_subtree(t))
    return 0;

  /* Victim is the calling process itself (mmap maps into the caller's own
   * address space; there is no separate victim process). */
  emit_deny(AC_ENF_INJECT, me, me);
  return -EPERM;
}
