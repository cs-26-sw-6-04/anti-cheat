/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include "common.bpf.h"

/* Converts a u32 pid to a decimal string in buf (must be at least 12 bytes).
 * Returns the number of characters written (without NUL terminator). */
static __always_inline int pid_to_str(__u32 pid, char *buf, int bufsz) {
  int i = bufsz - 1;
  buf[i] = '\0';
  if (pid == 0) {
    buf[--i] = '0';
    return 1;
  }
  while (pid > 0 && i > 0) {
    buf[--i] = '0' + (pid % 10);
    pid /= 10;
  }
  /* shift to front: source indices (i..bufsz-2) are always ahead of
   * destination indices (0..len-1), so the in-place copy is safe. */
  int len = bufsz - 1 - i;
  for (int j = 0; j < len && j < bufsz - 1; j++)
    buf[j] = buf[i + j];
  buf[len] = '\0';
  return len;
}

/* A3 audit result (docs/design-decisions.md §A3): /proc/<pid>/mem, maps,
 * smaps, auxv are already blocked by ptrace_access_check (AC_ENF_MEMORY).
 * Only status, cmdline, and environ are world-readable without a ptrace gate.
 * This enforcer fires ONLY for those three paths, preserving attribution
 * accuracy: mem/maps/smaps/auxv events remain attributed to AC_ENF_MEMORY. */
static __always_inline int is_uncovered_proc_file(struct dentry *de) {
  /* "cmdline" is 7 chars; "environ" is 7 chars; "status" is 6 chars.
   * Read 8 bytes to fit all of them (7 chars + NUL). */
  char name[8] = {};
  bpf_core_read_str(name, sizeof(name), BPF_CORE_READ(de, d_name.name));

  /* "status"  s-t-a-t-u-s-\0 */
  if (name[0] == 's' && name[1] == 't' && name[2] == 'a' &&
      name[3] == 't' && name[4] == 'u' && name[5] == 's' &&
      name[6] == '\0')
    return 1;

  /* "cmdline" c-m-d-l-i-n-e-\0 */
  if (name[0] == 'c' && name[1] == 'm' && name[2] == 'd' &&
      name[3] == 'l' && name[4] == 'i' && name[5] == 'n' &&
      name[6] == 'e' && name[7] == '\0')
    return 1;

  /* "environ" e-n-v-i-r-o-n-\0 */
  if (name[0] == 'e' && name[1] == 'n' && name[2] == 'v' &&
      name[3] == 'i' && name[4] == 'r' && name[5] == 'o' &&
      name[6] == 'n' && name[7] == '\0')
    return 1;

  return 0;
}

SEC("lsm.s/file_open")            /* sleepable: required for dentry inspection */
int BPF_PROG(proc_enforce, struct file *file, int ret) {
  if (ret)
    return ret;

  if (!ac_protected_root_pid)
    return 0;

  /* Read dentry name chain: /proc/<target_pid>/<file>.
   * For a path /proc/1234/status:
   *   de->d_name.name          == "status"
   *   parent->d_name.name      == "1234"
   *   grandparent->d_name.name == "proc" */
  struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
  struct dentry *parent = BPF_CORE_READ(de, d_parent);
  struct dentry *gp = BPF_CORE_READ(parent, d_parent);

  /* Check grandparent name == "proc" (4 bytes + NUL). */
  char gp_name[8] = {};
  bpf_core_read_str(gp_name, sizeof(gp_name),
                    BPF_CORE_READ(gp, d_name.name));
  if (gp_name[0] != 'p' || gp_name[1] != 'r' ||
      gp_name[2] != 'o' || gp_name[3] != 'c' || gp_name[4] != '\0')
    return 0;

  /* Check parent name == ac_protected_root_pid as decimal string. */
  char expected[12] = {};
  pid_to_str(ac_protected_root_pid, expected, sizeof(expected));
  char parent_name[12] = {};
  bpf_core_read_str(parent_name, sizeof(parent_name),
                    BPF_CORE_READ(parent, d_name.name));

  /* BPF cannot call strncmp directly in older kernels — compare byte by byte
   * for up to 11 decimal digits. */
#pragma unroll
  for (int i = 0; i < 11; i++) {
    if (expected[i] != parent_name[i])
      return 0;
    if (expected[i] == '\0')
      break;
  }

  /* Only fire for the paths not covered by ptrace_access_check (A3 audit):
   * status, cmdline, environ. */
  if (!is_uncovered_proc_file(de))
    return 0;

  __u32 me = cur_pid();
  /* Privacy constraint: do not log the filename component (de->d_name.name).
   * The event carries only attacker pid and victim (protected root) pid. */
  emit_deny(AC_ENF_PROC, me, ac_protected_root_pid);
  return -EPERM;
}
