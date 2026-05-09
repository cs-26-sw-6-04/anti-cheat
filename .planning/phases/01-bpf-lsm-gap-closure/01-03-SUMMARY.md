---
phase: 01-bpf-lsm-gap-closure
plan: "03"
subsystem: bpf-lsm
tags:
  - bpf
  - lsm
  - execve
  - bprm_check_security
  - tests

dependency_graph:
  requires:
    - 01-02-PLAN.md
  provides:
    - src/bpf/execve.bpf.h
    - tests/execve.cpp
    - exec_child target factory
  affects:
    - src/bpf/enforcers.bpf.c

tech_stack:
  added:
    - lsm/bprm_check_security hook (execve LSM enforcer)
    - exec_child() target factory with go-signal synchronisation
  patterns:
    - BPF LSM hook returning -EPERM to block execve from descendants of protected root
    - Root exemption: me == ac_protected_root_pid -> return 0 (startup exec allowed)
    - go-signal barrier (getchar before fork): session open before grandchild created

key_files:
  created:
    - src/bpf/execve.bpf.h
    - tests/execve.cpp
  modified:
    - src/bpf/enforcers.bpf.c
    - tests/support/targets.hpp
    - tests/support/targets.cpp

decisions:
  - "A2 option-a applied: execve enforcer fires only on descendants of ac_protected_root_pid, not root itself"
  - "emit_deny carries only pids (no bprm->file path) -- privacy constraint"
  - "exec_child factory uses grandchild fork-after-go-signal to eliminate race between session open and exec"

metrics:
  duration_seconds: 2006
  completed_date: "2026-05-09"
  tasks_completed: 2
  tasks_total: 2
  files_created: 3
  files_modified: 3
---

# Phase 01 Plan 03: execve Enforcer Summary

**One-liner:** BPF LSM execve enforcer (lsm/bprm_check_security) blocking descendant exec with root exemption, exec_child factory with go-signal synchronisation, and two-section integration tests.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create execve.bpf.h -- lsm/bprm_check_security enforcer | 9349344 | src/bpf/execve.bpf.h, src/bpf/enforcers.bpf.c |
| 2 | Add exec_child factory and write execve.cpp tests | 17cb677 | tests/execve.cpp, tests/support/targets.hpp, tests/support/targets.cpp |

## What Was Built

**src/bpf/execve.bpf.h** — BPF LSM enforcer using `SEC("lsm/bprm_check_security")`. Implements the A2 option-a decision: fire only when `me != ac_protected_root_pid` AND `is_in_protected_subtree(t)`. The root's own startup exec is exempted by returning 0 immediately when `me == ac_protected_root_pid`. Descendants attempting exec receive `emit_deny(AC_ENF_EXECVE, me, me)` + return -EPERM. No filename/path logged (privacy constraint).

**src/bpf/enforcers.bpf.c** — Updated to `#include "execve.bpf.h"` immediately after `inject.bpf.h`. Comment block extended with execve domain description.

**tests/support/targets.hpp** — Added `exec_child()` declaration with synchronisation contract documented in comment.

**tests/support/targets.cpp** — Implemented `exec_child()` factory: root prints READY, blocks on `getchar()` (go-signal from `t.release()`), forks grandchild that calls `execvp("/bin/true")`. Grandchild exits 1 if exec was blocked (EPERM), 0 if it succeeded. Root reports `FLAG exec_ok` or `FLAG exec_blocked` after EOF on stdin.

**tests/execve.cpp** — Three test sections:
- "attack succeeds (no enforcer)": exec_child without session, FLAG == "exec_ok"
- "protected": session opened before `t.release()`; grandchild exec blocked; AC_ENF_EXECVE event collected; FLAG == "exec_blocked"
- "root startup exec passes": negative test verifying no AC_ENF_EXECVE event fires for flag_secret target

## Deviations from Plan

None — plan executed exactly as written.

## Environment Note

Build verification (`cmake --build --preset conan-debug`) could not be run: the execution environment is macOS which lacks `bpftool` and the BPF toolchain required for cross-compilation. This is expected — the BPF TU compiles for Linux only. All acceptance criteria not requiring a live build were verified with grep checks. Full build and `ctest -R execve` verification must be performed on a Linux host with BPF LSM enabled (`CONFIG_BPF_LSM=y`, `lsm=...,bpf`).

## Threat Model Coverage

| Threat | Mitigation |
|--------|------------|
| T-03-01: descendant exec of attacker binary | lsm/bprm_check_security returns -EPERM before binary handler runs |
| T-03-02: prior LSM deny passthrough | `if (ret) return ret;` as first statement |
| T-03-03: blocking root startup exec | Explicit `me == ac_protected_root_pid` exemption; negative test verifies |
| T-03-04: race -- grandchild forks before session open | go-signal getchar before fork; test calls open_or_skip before release() |
| T-03-05: bprm->file path disclosure | emit_deny carries only pids; no filename in event |

## Self-Check: PASSED

- src/bpf/execve.bpf.h exists: FOUND
- src/bpf/enforcers.bpf.c contains `#include "execve.bpf.h"`: FOUND
- tests/execve.cpp exists: FOUND
- tests/support/targets.hpp contains exec_child: FOUND
- Task 1 commit 9349344: FOUND
- Task 2 commit 17cb677: FOUND
