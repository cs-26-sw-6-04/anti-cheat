# Roadmap

## Phase 1: BPF LSM Gap Closure

**Goal:** Add the remaining BPF LSM enforcers (inject/mmap, execve, and proc/openat coverage audit) with full test coverage and documentation, closing the gap between the report's stated monitor list and what the current LSM-only architecture can deliver.

**Requirements:** REQ-01, REQ-02, REQ-03, REQ-04, REQ-05, REQ-06, REQ-07, REQ-08, REQ-09

**Depends on:** (none)

**Status:** Planning

**Plans:** 4 plans

Plans:
- [~] 01-01-PLAN.md — Design decisions and /proc coverage audit (paused: awaiting A3 Linux audit + A1/A2/A6 decisions)
- [ ] 01-02-PLAN.md — inject enforcer end-to-end (bpf hook, enum, factory, tests, CLI)
- [ ] 01-03-PLAN.md — execve enforcer end-to-end (bpf hook, factory, tests)
- [ ] 01-04-PLAN.md — proc enforcer conditional + docs/testing.md + ac.h comment polish
