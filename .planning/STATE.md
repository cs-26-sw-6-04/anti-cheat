---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: executing
last_updated: "2026-05-09T15:12:41.105Z"
last_activity: 2026-05-09
progress:
  total_phases: 1
  completed_phases: 0
  total_plans: 4
  completed_plans: 0
  percent: 0
---

# Project State

**Project:** anti-cheat — eBPF BPF LSM runtime integrity enforcement
**Status:** Ready to execute
**Last Activity:** 2026-05-09

## Current Phase

Phase 1 — BPF LSM Gap Closure (Ready to plan)

## Completed Phases

None yet.

## Implementation Status

Already implemented in `src/`:

- `AC_ENF_SELFPROTECT` — `lsm/ptrace_access_check` protecting loader (ac_self_pid)
- `AC_ENF_MEMORY` — `lsm/ptrace_access_check` protecting protected subtree (covers ptrace, process_vm_readv, process_vm_writev, /proc/PID/mem)
- `ac_open`, `ac_spawn_and_protect`, `ac_poll`, `ac_next_event` — session lifecycle API
- `src/cli/` — `ac` CLI wrapping spawn+protect
- Tests: memory.cpp, self_protect.cpp, subtree.cpp, api.cpp

Not yet implemented:

- `inject` enforcer — file_mmap/file_mprotect for PROT_EXEC mapping blocking
- `execve` enforcer — bprm_check_security for unauthorized exec detection
- Extended `/proc` path coverage for openat beyond what ptrace_access_check covers

## Architecture Invariants

- LSM hooks only (no tracepoints/kprobes/syscall tracking)
- Enforcers split by victim domain, not operation kind
- No central on/off toggle — rodata-anchored domain checks only
- Privacy: no syscall args, no process trees, no memory content logged
- Single BPF TU: enforcers.bpf.c includes all *.bpf.h enforcer headers
