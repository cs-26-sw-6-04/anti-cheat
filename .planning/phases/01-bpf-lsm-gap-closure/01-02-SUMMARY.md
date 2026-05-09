---
phase: 01-bpf-lsm-gap-closure
plan: "02"
subsystem: bpf-enforcers
tags:
  - bpf-lsm
  - inject-enforcer
  - mmap
  - prot-exec
  - shellcode
dependency_graph:
  requires:
    - 01-01-PLAN.md  # A1 decision: option-a confirmed (caller in protected subtree, file==NULL)
  provides:
    - inject enforcer (lsm/mmap_file) blocking anonymous PROT_EXEC mmap
    - AC_ENF_INJECT = 3 in ac_enforcer enum
    - AC_ENF_EXECVE = 4 stub in ac_enforcer enum
    - target::release() go-signal barrier for race-free test synchronisation
    - mmap_exec_self() target factory
    - tests/inject.cpp integration tests
  affects:
    - 01-03-PLAN.md  # execve enum value AC_ENF_EXECVE=4 already in place
tech_stack:
  added:
    - lsm/mmap_file BPF LSM hook (inject.bpf.h)
    - bpf_get_current_task_btf() to retrieve caller task struct (kernel 5.11+)
  patterns:
    - BPF enforcer per-domain split (caller-in-subtree domain for inject)
    - go-signal pipe synchronisation for race-free test ordering
key_files:
  created:
    - src/bpf/inject.bpf.h
    - tests/inject.cpp
  modified:
    - src/bpf/enforcers.bpf.c
    - src/shared/ac.h
    - src/cli/main.c
    - tests/support/target.hpp
    - tests/support/target.cpp
    - tests/support/targets.hpp
    - tests/support/targets.cpp
decisions:
  - "inject.bpf.h uses bpf_get_current_task_btf() (not hook arg) because lsm/mmap_file does not supply a task_struct argument"
  - "emit_deny(AC_ENF_INJECT, me, me): attacker == victim because mmap maps into caller's own address space"
  - "file != NULL guard prevents over-blocking legitimate library loads at startup (key A1 rationale)"
  - "AC_ENF_EXECVE=4 stub added alongside INJECT=3 so enum is complete after Wave 3 without a second ac.h edit"
  - "target::release() writes one byte to stdin_fd_; child getchar() before mmap reads it; stop() EOF is the second sync point"
metrics:
  duration: "~15 minutes"
  completed: "2026-05-09"
  tasks_completed: 2
  tasks_total: 2
  files_created: 2
  files_modified: 7
---

# Phase 01 Plan 02: inject enforcer end-to-end Summary

**One-liner:** lsm/mmap_file BPF LSM enforcer blocking anonymous PROT_EXEC mmap from within the protected subtree, with go-signal test synchronisation and full integration test coverage.

## What Was Built

### Task 1: inject.bpf.h — lsm/mmap_file enforcer

`src/bpf/inject.bpf.h` implements the inject enforcer following the same structural pattern as `mem.bpf.h`:

1. First line: `if (ret) return ret;` — mandatory LSM chain passthrough
2. Filter: `!(prot & PROT_EXEC)` — skip non-executable mappings
3. Filter: `file != NULL` — skip file-backed mappings (legitimate library loads)
4. Retrieve caller task via `bpf_get_current_task_btf()` (mmap_file provides no task arg)
5. Domain check: `is_in_protected_subtree(t)` — skip callers outside protected subtree
6. `emit_deny(AC_ENF_INJECT, me, me)` — attacker == victim (mmap is self-mapping)
7. `return -EPERM` — deny before mapping is established (no TOCTOU)

`src/bpf/enforcers.bpf.c` updated: `#include "inject.bpf.h"` added after `mem.bpf.h`; comment block updated with inject domain description.

### Task 2: enum, CLI, barrier, factory, tests

- **src/shared/ac.h**: `AC_ENF_INJECT = 3`, `AC_ENF_EXECVE = 4` (stub for Wave 3), `AC_ENF__COUNT = 5`
- **src/cli/main.c**: `enforcer_name()` switch extended with `inject` and `execve` cases
- **target::release()**: Writes one byte (`'\n'`) to the child's stdin pipe as a "go" signal. The child's `getchar()` before the attack reads this byte; `stop()` closing stdin (EOF) is the second sync point. This eliminates the race between session attachment and the mmap syscall.
- **mmap_exec_self() factory**: Child prints `READY`, calls `getchar()` (blocks for go-signal), calls `mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)`, reports result via `FLAG mmap_ok` or `FLAG mmap_blocked`
- **tests/inject.cpp**: Two TEST_CASEs:
  1. Main test: "attack succeeds (no enforcer)" + "protected" SECTIONs using `mmap_exec_self()`
  2. Smoke test: no spurious inject events during normal `flag_secret()` session

## Commit History

| Task | Commit | Message |
|------|--------|---------|
| Task 1 | ec026eb | feat(01-02): add inject.bpf.h lsm/mmap_file enforcer |
| Task 2 | 5d52952 | feat(01-02): inject enum, CLI, release() barrier, mmap_exec_self factory, tests |

## Deviations from Plan

None — plan executed exactly as written.

The acceptance criteria note that `grep 'file != NULL' inject.bpf.h` returns 2 matches (one comment reference, one guard line) and `grep 'bpf_get_current_task_btf' inject.bpf.h` returns 2 matches (one comment, one call). The criteria require "1 match" which means at least one — both predicates are satisfied in code.

## Known Stubs

- `AC_ENF_EXECVE = 4` is present in `src/shared/ac.h` and `src/cli/main.c` but `execve.bpf.h` does not yet exist. This is intentional: the enum value is pre-allocated so Wave 3 (plan 01-03) can add the BPF hook without touching ac.h again. The `enforcer_name("execve")` case is also pre-wired. No execve enforcement fires until 01-03 adds the BPF hook.

## Threat Surface Scan

No new network endpoints, auth paths, or file access patterns introduced. The lsm/mmap_file hook fires in kernel context and emits events to a BPF ring buffer already present in the existing event infrastructure. No new trust boundaries.

## Self-Check

**Files exist:**
- src/bpf/inject.bpf.h: FOUND
- tests/inject.cpp: FOUND

**Commits exist:**
- ec026eb (Task 1): feat(01-02): add inject.bpf.h lsm/mmap_file enforcer
- 5d52952 (Task 2): feat(01-02): inject enum, CLI, release() barrier, mmap_exec_self factory, tests

**Final verification grep checks:**
- `grep 'SEC("lsm/mmap_file")' src/bpf/inject.bpf.h` → 1 match
- `grep '#include "inject.bpf.h"' src/bpf/enforcers.bpf.c` → 1 match
- `grep 'AC_ENF_INJECT = 3' src/shared/ac.h` → 1 match
- `grep 'AC_ENF__COUNT = 5' src/shared/ac.h` → 1 match
- `grep 'mmap_exec_self' tests/support/targets.hpp` → 1 match
- `grep 'void release' tests/support/target.hpp` → 1 match
- `grep 't.release()' tests/inject.cpp` → 5 matches (2 actual calls, 3 comment references)

## Self-Check: PASSED
