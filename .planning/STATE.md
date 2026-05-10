---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: milestone_complete
last_updated: "2026-05-10T05:15:16.639Z"
last_activity: 2026-05-10
progress:
  total_phases: 1
  completed_phases: 2
  total_plans: 4
  completed_plans: 4
  percent: 200
---

# Project State

**Project:** anti-cheat — eBPF BPF LSM runtime integrity enforcement
**Status:** Milestone complete
**Last Activity:** 2026-05-10

## Current Phase

Phase 1 — BPF LSM Gap Closure (Complete — all 4 plans executed)

## Completed Phases

- Phase 1: BPF LSM Gap Closure (Plans 01-04 all complete)

## Implementation Status

Implemented across all four plans:

- `AC_ENF_SELFPROTECT` — `lsm/ptrace_access_check` protecting loader (ac_self_pid)
- `AC_ENF_MEMORY` — `lsm/ptrace_access_check` protecting protected subtree (covers ptrace, process_vm_readv, process_vm_writev, /proc/PID/mem)
- `ac_open`, `ac_spawn_and_protect`, `ac_poll`, `ac_next_event` — session lifecycle API
- `src/cli/` — `ac` CLI wrapping spawn+protect
- `AC_ENF_INJECT = 3` — `lsm/mmap_file` hook blocking anonymous PROT_EXEC mmap from within the protected subtree
- `AC_ENF_EXECVE = 4` — `lsm/bprm_check_security` hook blocking descendant exec from protected subtree; root exemption for startup exec
- `AC_ENF_PROC = 5` — `lsm.s/file_open` hook blocking open of /proc/<pid>/{status,cmdline,environ} (A3-confirmed uncovered paths)
- `AC_ENF__COUNT = 6`
- Tests: memory.cpp, self_protect.cpp, subtree.cpp, api.cpp, inject.cpp, execve.cpp, proc.cpp

## Architecture Invariants

- LSM hooks only (no tracepoints/kprobes/syscall tracking)
- Enforcers split by victim domain, not operation kind
- No central on/off toggle — rodata-anchored domain checks only
- Privacy: no syscall args, no process trees, no memory content logged
- Single BPF TU: enforcers.bpf.c includes all *.bpf.h enforcer headers

## Architecture Invariants

- LSM hooks only (no tracepoints/kprobes/syscall tracking)
- Enforcers split by victim domain, not operation kind
- No central on/off toggle — rodata-anchored domain checks only
- Privacy: no syscall args, no process trees, no memory content logged
- Single BPF TU: enforcers.bpf.c includes all *.bpf.h enforcer headers
