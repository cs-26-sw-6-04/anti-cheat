<!--
SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# BPF LSM Gap Closure -- Design Decisions

This document records the four design decisions (A1, A2, A3, A6) that gate Wave 2-4
implementation. Wave 2-4 executors must read this file before touching `inject.bpf.h`,
`execve.bpf.h`, `proc.bpf.h`, or `tests/support/targets.*`.

## A1: inject enforcer victim domain

**Decision:** option-a -- fire when the protected process (or descendant) maps anonymous
PROT_EXEC.

**Rationale:** An external process cannot mmap into another process's address space directly;
that path requires ptrace (already blocked by AC_ENF_MEMORY). The remaining injection vector
is the game process itself allocating anonymous executable pages (shellcode injection from
within the subtree).

**JIT note:** No JIT runtime is present in the game target. V8, Mono, JVM, LuaJIT, and Wine
are absent. The anonymous PROT_EXEC filter therefore carries no risk of false positives from
legitimate JIT code generation.

**Impact on inject.bpf.h:** Fire when caller is in protected subtree AND (prot & PROT_EXEC)
AND file == NULL (anonymous mapping). Whitelisted PIDs pass through without action.

## A2: execve first-exec filter

**Decision:** a2-option-a -- fire only on descendants of ac_protected_root_pid, not the root
itself.

**Rationale:** ac_spawn_and_protect attaches BPF before releasing the child via the barrier
pipe. The root's first action is to exec the game binary -- this exec must not be blocked.
Descendants should not exec without permission. Consistent with GOALS.md "no central toggle."

**Filter rule:** Fire only when `me != ac_protected_root_pid` AND `is_in_protected_subtree(t)`
is true.

## A3: /proc/<pid>/ coverage audit

**Note:** Results below are inferred from Linux kernel source analysis. Empirical
verification on a Linux host with BPF LSM enabled (CONFIG_BPF_LSM=y, lsm=...,bpf) is
pending and should be performed before finalising Wave 4 (proc enforcer implementation).

**Audited paths:**

| Path | ptrace_access_check blocks? |
|------|-----------------------------|
| /proc/\<pid\>/mem     | YES -- COVERED by ptrace_access_check (inferred) |
| /proc/\<pid\>/maps    | YES -- COVERED by ptrace_access_check (inferred) |
| /proc/\<pid\>/smaps   | YES -- COVERED by ptrace_access_check (inferred) |
| /proc/\<pid\>/auxv    | YES -- COVERED by ptrace_access_check (inferred) |
| /proc/\<pid\>/status  | NO  -- UNCOVERED -- proc enforcer needed (inferred) |
| /proc/\<pid\>/cmdline | NO  -- UNCOVERED -- proc enforcer needed (inferred) |
| /proc/\<pid\>/environ | NO  -- UNCOVERED -- proc enforcer needed (inferred) |

**Kernel rationale:** `proc_mem_open` and `proc_maps_open` call `ptrace_may_access` /
`security_ptrace_access_check` internally (kernel >= 4.x). The `status`, `cmdline`, and
`environ` files are world-readable or owner-only without a ptrace gate; they do not invoke
the LSM hook and therefore bypass AC_ENF_MEMORY.

**Outcome:** proc.bpf.h IS needed for: status, cmdline, environ. The Wave 4 proc enforcer
must hook `lsm/file_open` and filter on access to `/proc/<target_pid>/` paths that are not
gated by ptrace_access_check.

## A6: test harness for inject/execve

**Decision:** a6-option-b -- new target factories (mmap_exec_self, exec_child).

**Rationale:** For inject and execve tests, the attack must originate from inside the
protected subtree (the caller must be a member of the protected process tree for the enforcer
to fire). The external `run_attacker` pattern used by memory.cpp is not applicable. New
target factories that perform the malicious action internally are the minimal-impact approach
that requires no changes to the run_scenario harness.

**New factories needed:** `mmap_exec_self()` and `exec_child()` in
`tests/support/targets.{hpp,cpp}`.

**Test structure:** Each scenario has two sections: "attack succeeds" (spawns without
session, verifies syscall succeeds) and "protected" (spawns with session, verifies syscall
is blocked by the enforcer).
