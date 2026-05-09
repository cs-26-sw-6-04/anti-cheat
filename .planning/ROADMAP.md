# Roadmap

## Phase 1: BPF LSM Gap Closure

**Goal:** Add the remaining BPF LSM enforcers (inject/mmap, execve, and proc/openat coverage audit) with full test coverage and documentation, closing the gap between the report's stated monitor list and what the current LSM-only architecture can deliver.

**Requirements:** REQ-01, REQ-02, REQ-03, REQ-04, REQ-05, REQ-06, REQ-07, REQ-08, REQ-09

**Depends on:** (none)

**Status:** Executing

**Plans:** 3/4 plans executed

Plans:
- [x] 01-01-PLAN.md — Design decisions and /proc coverage audit (complete: A1/A2/A3/A6 recorded in docs/design-decisions.md)
- [x] 01-02-PLAN.md — inject enforcer end-to-end (complete: inject.bpf.h, AC_ENF_INJECT=3, mmap_exec_self factory, tests/inject.cpp)
- [x] 01-03-PLAN.md — execve enforcer end-to-end (complete: execve.bpf.h, lsm/bprm_check_security, exec_child factory, tests/execve.cpp)
- [ ] 01-04-PLAN.md — proc enforcer conditional + docs/testing.md + ac.h comment polish
