---
phase: 1
slug: bpf-lsm-gap-closure
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-05-09
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Catch2 3.11.0 (Conan) via CMake CTest |
| **Config file** | `CMakeLists.txt` (tests target) |
| **Quick run command** | `cmake --build --preset conan-debug && sudo ctest --preset conan-debug -R inject\|execve\|proc` |
| **Full suite command** | `cmake --workflow --preset conan-debug && sudo ctest --preset conan-debug` |
| **Estimated runtime** | ~30–60 seconds (requires root for BPF loading) |

---

## Sampling Rate

- **After every task commit:** Run quick run command
- **After every plan wave:** Run full suite command
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 1-01-01 | 01 | 1 | REQ-04 | — | ac_enforcer enum has AC_ENF_INJECT, AC_ENF_EXECVE | unit | `grep -r AC_ENF_INJECT src/shared/ac.h` | ⬜ | ⬜ pending |
| 1-01-02 | 01 | 1 | REQ-01 | — | inject enforcer blocks external PROT_EXEC mmap | integration | `sudo ctest --preset conan-debug -R inject` | ❌ W0 | ⬜ pending |
| 1-01-03 | 01 | 1 | REQ-02 | — | execve enforcer blocks unauthorized exec | integration | `sudo ctest --preset conan-debug -R execve` | ❌ W0 | ⬜ pending |
| 1-01-04 | 01 | 1 | REQ-03 | — | proc/openat coverage audit documented and gaps closed | integration | `sudo ctest --preset conan-debug -R proc\|mem` | ⬜ | ⬜ pending |
| 1-02-01 | 02 | 2 | REQ-05 | — | inject test cases added, attack/protected sections present | unit | `grep -r AC_ENF_INJECT tests/inject.cpp` | ❌ W0 | ⬜ pending |
| 1-02-02 | 02 | 2 | REQ-06 | — | execve test cases added, attack/protected sections present | unit | `grep -r AC_ENF_EXECVE tests/execve.cpp` | ❌ W0 | ⬜ pending |
| 1-02-03 | 02 | 2 | REQ-07 | — | proc test cases cover any /proc/<pid>/ gaps | unit | `grep -r AC_ENF_PROC tests/proc.cpp` | ❌ W0 | ⬜ pending |
| 1-03-01 | 03 | 3 | REQ-08 | — | ac CLI reflects new enforcer names | unit | `grep -r AC_ENF_INJECT src/cli/` | ⬜ | ⬜ pending |
| 1-03-02 | 03 | 3 | REQ-09 | — | docs/testing.md updated with new enforcer domains | manual | N/A | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/inject.cpp` — stub test file for REQ-01/REQ-05
- [ ] `tests/execve.cpp` — stub test file for REQ-02/REQ-06
- [ ] `tests/proc.cpp` — stub test file for REQ-03/REQ-07 (if gaps found)
- [ ] CMakeLists.txt updated to include new test targets

*Existing Catch2 infrastructure in `tests/` is assumed from STATE.md; Wave 0 adds only new test stubs.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| /proc coverage audit finding documented | REQ-03 | Requires empirical kernel-level check | Read `src/bpf/mem.bpf.h`, attach enforcer, attempt `/proc/<pid>/mem` open, verify blocked |
| ac.h comments explain new enforcer IDs | REQ-09 | Content review | Read `src/shared/ac.h`, verify AC_ENF_INJECT and AC_ENF_EXECVE have descriptive comments |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
