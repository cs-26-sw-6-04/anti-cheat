---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: executing
last_updated: "2026-05-09T21:35:11.090Z"
last_activity: 2026-05-09
progress:
  total_phases: 1
  completed_phases: 0
  total_plans: 4
  completed_plans: 3
  percent: 75
---

# Project State

**Project:** anti-cheat — eBPF BPF LSM runtime integrity enforcement
**Status:** Executing Phase 01 (Plan 03 complete — ready for Plan 04)
**Last Activity:** 2026-05-09

## Current Phase

Phase 1 — BPF LSM Gap Closure (In progress — Plan 03 complete; Plan 04 next)

## Completed Phases

None yet.

## Implementation Status

Already implemented in `src/`:

- `AC_ENF_SELFPROTECT` — `lsm/ptrace_access_check` protecting loader (ac_self_pid)
- `AC_ENF_MEMORY` — `lsm/ptrace_access_check` protecting protected subtree (covers ptrace, process_vm_readv, process_vm_writev, /proc/PID/mem)
- `ac_open`, `ac_spawn_and_protect`, `ac_poll`, `ac_next_event` — session lifecycle API
- `src/cli/` — `ac` CLI wrapping spawn+protect
- Tests: memory.cpp, self_protect.cpp, subtree.cpp, api.cpp

Now implemented (Plan 02):

- `AC_ENF_INJECT = 3` — `lsm/mmap_file` hook blocking anonymous PROT_EXEC mmap from within the protected subtree
- `target::release()` — go-signal barrier for race-free inject test synchronisation
- `mmap_exec_self()` factory + `tests/inject.cpp` integration tests
- `AC_ENF_EXECVE = 4` and `AC_ENF__COUNT = 5` pre-allocated in enum (execve.bpf.h comes in Plan 03)

Now implemented (Plan 03):

- `AC_ENF_EXECVE = 4` — `lsm/bprm_check_security` hook blocking descendant exec from protected subtree
- Root exemption: `me == ac_protected_root_pid` returns 0 (startup exec allowed)
- `exec_child()` target factory with go-signal synchronisation (grandchild forked after session open)
- `tests/execve.cpp` integration tests (attack-succeeds + protected + negative root-exemption sections)

Not yet implemented:

- Extended `/proc` path coverage for openat beyond what ptrace_access_check covers (Plan 04)

## Architecture Invariants

- LSM hooks only (no tracepoints/kprobes/syscall tracking)
- Enforcers split by victim domain, not operation kind
- No central on/off toggle — rodata-anchored domain checks only
- Privacy: no syscall args, no process trees, no memory content logged
- Single BPF TU: enforcers.bpf.c includes all *.bpf.h enforcer headers
