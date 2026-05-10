---
phase: 01-bpf-lsm-gap-closure
verified: 2026-05-10T00:00:00Z
status: human_needed
score: 9/9 must-haves verified (static); 2 items require Linux host run
overrides_applied: 0
human_verification:
  - test: "Linux build + full ctest run"
    expected: "cmake --workflow --preset conan-debug succeeds and sudo ctest --preset conan-debug --output-on-failure passes all tests including inject, execve, proc"
    why_human: "BPF programs (inject.bpf.h, execve.bpf.h, proc.bpf.h) require bpftool and a live Linux BPF LSM kernel to compile and load. bpf_get_current_task_btf (kernel 5.11+), lsm.s/file_open sleepable variant, and dentry chain CO-RE reads in proc.bpf.h cannot be validated by static grep. macOS lacks BPF toolchain entirely."
  - test: "A3 empirical verification: confirm ptrace_access_check coverage on target kernel"
    expected: "On Linux host with CONFIG_BPF_LSM=y: open(/proc/<pid>/mem), open(/proc/<pid>/maps), open(/proc/<pid>/smaps), open(/proc/<pid>/auxv) all return EPERM under AC_ENF_MEMORY session; open(/proc/<pid>/status), open(/proc/<pid>/cmdline), open(/proc/<pid>/environ) are NOT blocked by AC_ENF_MEMORY but ARE blocked by AC_ENF_PROC. No path mis-attributed."
    why_human: "A3 audit results are inferred from Linux kernel source analysis only — not measured empirically. Plan 01-01 SUMMARY explicitly states: 'Empirical verification should be done before Wave 4 finalisation.' Plan 01-04 SUMMARY repeats this caveat. If mem/maps/smaps/auxv are NOT gated by ptrace_access_check on the actual kernel version used, proc.bpf.h's narrow scope leaves those paths uncovered."
  - test: "proc.bpf.h self-introspection false-positive check"
    expected: "A game binary wrapped by ac that reads /proc/self/status (or cmdline, environ) at startup does NOT get blocked by AC_ENF_PROC, OR the false positive is acceptable / a future fix is planned"
    why_human: "Plan 01-04 SUMMARY documents a known threat_flag: glibc and Go runtime read /proc/self/status during startup. proc.bpf.h fires on any opener including the protected process itself (no self-exemption). Only relevant for real game binaries — the test target (flag_secret) does not self-introspect."
---

# Phase 01: BPF LSM Gap Closure Verification Report

**Phase Goal:** Add the remaining BPF LSM enforcers (inject/mmap, execve, and proc/openat coverage audit) with full test coverage and documentation, closing the gap between the report's stated monitor list and what the current LSM-only architecture can deliver.

**Verified:** 2026-05-10T00:00:00Z
**Status:** human_needed
**Re-verification:** No — initial verification

**Platform note:** This verification was run on macOS. Build and runtime checks (`cmake --build`, `ctest`) cannot be executed. All checks are static (file existence, grep). Linux build and test run are required for final gate passage (see Human Verification Required section).

## Goal Achievement

### Observable Truths

| #  | Truth | Status | Evidence |
|----|-------|--------|----------|
| 1  | `lsm/mmap_file` hook fires when the protected process maps anonymous PROT_EXEC | ✓ VERIFIED | `src/bpf/inject.bpf.h` line 11: `SEC("lsm/mmap_file")`, guards `prot & PROT_EXEC` + `file == NULL`, calls `emit_deny(AC_ENF_INJECT, me, me)` + `return -EPERM` |
| 2  | File-backed PROT_EXEC mappings (legitimate library loads) pass through unblocked | ✓ VERIFIED | `inject.bpf.h` line 26–27: `if (file != NULL) return 0;` — explicit file-backed exemption present |
| 3  | Non-protected processes unaffected by inject enforcer | ✓ VERIFIED | `inject.bpf.h` calls `is_in_protected_subtree(t)` and returns 0 if false; only callers in subtree are blocked |
| 4  | `lsm/bprm_check_security` hook fires when a descendant of the protected root execs | ✓ VERIFIED | `src/bpf/execve.bpf.h` line 11: `SEC("lsm/bprm_check_security")`, descendant check via `is_in_protected_subtree(t)`, `emit_deny(AC_ENF_EXECVE, me, me)` + `return -EPERM` |
| 5  | Root process startup exec is NOT blocked by execve enforcer | ✓ VERIFIED | `execve.bpf.h` lines 29–30: `if (me == ac_protected_root_pid) return 0;` — explicit root exemption |
| 6  | proc enforcer (lsm.s/file_open) blocks open of /proc/<pid>/{status,cmdline,environ} | ✓ VERIFIED | `src/bpf/proc.bpf.h` line 65: `SEC("lsm.s/file_open")`, dentry chain walk (grandparent=="proc", parent==target pid string), `is_uncovered_proc_file()` filters to {status,cmdline,environ} only, `emit_deny(AC_ENF_PROC, me, ac_protected_root_pid)` + `return -EPERM` |
| 7  | AC_ENF_INJECT=3, AC_ENF_EXECVE=4, AC_ENF_PROC=5, AC_ENF__COUNT=6 in enum | ✓ VERIFIED | `src/shared/ac.h` lines 36, 40, 45, 46 confirm exact values |
| 8  | enforcer_name() returns correct names for all new enforcers | ✓ VERIFIED | `src/cli/main.c` cases: `AC_ENF_INJECT→"inject"`, `AC_ENF_EXECVE→"execve"`, `AC_ENF_PROC→"proc"` |
| 9  | Test coverage: inject, execve, proc tests exist with attack-succeeds and protected sections; design decisions documented | ✓ VERIFIED | `tests/inject.cpp`, `tests/execve.cpp`, `tests/proc.cpp` all exist with correct structure; `docs/design-decisions.md` has A1/A2/A3/A6 sections; `docs/testing.md` documents all enforcer domains |

**Score:** 9/9 truths verified (static analysis)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/bpf/inject.bpf.h` | SEC("lsm/mmap_file"), emit_deny(AC_ENF_INJECT), file==NULL guard | ✓ VERIFIED | All three patterns confirmed present |
| `src/bpf/execve.bpf.h` | SEC("lsm/bprm_check_security"), root exemption, emit_deny(AC_ENF_EXECVE) | ✓ VERIFIED | All three patterns confirmed present |
| `src/bpf/proc.bpf.h` | SEC("lsm.s/file_open"), dentry walk, emit_deny(AC_ENF_PROC) | ✓ VERIFIED | Sleepable variant, pid_to_str helper, is_uncovered_proc_file filter for {status,cmdline,environ} |
| `src/shared/ac.h` | AC_ENF_INJECT=3, AC_ENF_EXECVE=4, AC_ENF_PROC=5, AC_ENF__COUNT=6 | ✓ VERIFIED | Exact values confirmed; descriptive comments for each new enforcer |
| `src/cli/main.c` | enforcer_name() cases for inject/execve/proc | ✓ VERIFIED | All three cases present before default: |
| `tests/inject.cpp` | AC_ENF_INJECT, attack-succeeds + protected sections, t.release() calls | ✓ VERIFIED | 3 AC_ENF_INJECT references, 5 t.release() references (2 calls + 3 in comments), mmap_exec_self factory |
| `tests/execve.cpp` | AC_ENF_EXECVE, attack-succeeds + protected + negative sections, t.release() | ✓ VERIFIED | 3 AC_ENF_EXECVE references, 4 t.release() references |
| `tests/proc.cpp` | AC_ENF_PROC, 3 test cases for status/cmdline/environ | ✓ VERIFIED | 3 AC_ENF_PROC references, one TEST_CASE per path |
| `tests/support/targets.hpp` | mmap_exec_self() and exec_child() declarations | ✓ VERIFIED | Both factories declared in ac::targets namespace |
| `tests/support/targets.cpp` | mmap_exec_self() and exec_child() implementations with PROT_EXEC and execvp | ✓ VERIFIED | mmap_exec_self has PROT_EXEC mmap; exec_child has execvp("/bin/true"); both use go-signal getchar() |
| `tests/support/target.hpp` | release() method declaration | ✓ VERIFIED | `void release();` in public section with synchronisation contract documented |
| `tests/support/target.cpp` | release() implementation writing go-signal byte | ✓ VERIFIED | `void target::release()` writes `'\n'` to stdin_fd_ |
| `docs/design-decisions.md` | A1/A2/A3/A6 sections, 7-path /proc table, no placeholder markers | ✓ VERIFIED | 4 `## A` sections confirmed; 9 /proc/ path references (7 table rows + header context); zero [FILL IN] markers |
| `docs/testing.md` | AC_ENF_INJECT/EXECVE/PROC documented with hook attribution | ✓ VERIFIED | All three enforcers documented with exact LSM hook names and file references |
| `src/bpf/enforcers.bpf.c` | #include for inject, execve, proc | ✓ VERIFIED | Three include directives present after mem.bpf.h |
| `tests/proc_audit.cpp` | Deleted (one-shot diagnostic) | ✓ VERIFIED | File does not exist — deleted as planned in Wave 4 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `src/bpf/inject.bpf.h` | `src/bpf/enforcers.bpf.c` | `#include "inject.bpf.h"` | ✓ WIRED | Line 28 of enforcers.bpf.c |
| `src/bpf/execve.bpf.h` | `src/bpf/enforcers.bpf.c` | `#include "execve.bpf.h"` | ✓ WIRED | Line 29 of enforcers.bpf.c |
| `src/bpf/proc.bpf.h` | `src/bpf/enforcers.bpf.c` | `#include "proc.bpf.h"` | ✓ WIRED | Line 30 of enforcers.bpf.c |
| `src/shared/ac.h` (AC_ENF_INJECT) | `tests/inject.cpp` | enum value used in REQUIRE | ✓ WIRED | 3 references in inject.cpp |
| `tests/support/targets.hpp` (mmap_exec_self) | `tests/inject.cpp` | factory invoked | ✓ WIRED | `targets::mmap_exec_self()()` called in two SECTION blocks |
| `tests/support/targets.hpp` (exec_child) | `tests/execve.cpp` | factory invoked | ✓ WIRED | `targets::exec_child()()` called in two SECTION blocks |
| `docs/design-decisions.md` (A1) | `src/bpf/inject.bpf.h` | A1 decision → file==NULL filter | ✓ WIRED | inject.bpf.h comment cites design-decisions.md A1; decision and implementation match |
| `docs/design-decisions.md` (A2) | `src/bpf/execve.bpf.h` | A2 decision → root exemption | ✓ WIRED | execve.bpf.h comment cites design-decisions.md A2; filter rule matches exactly |
| `docs/testing.md` | `src/bpf/inject.bpf.h` | LSM hook attribution (`mmap_file`) | ✓ WIRED | testing.md documents `lsm/mmap_file` for AC_ENF_INJECT |
| `docs/testing.md` | `src/bpf/execve.bpf.h` | LSM hook attribution (`bprm_check_security`) | ✓ WIRED | testing.md documents `lsm/bprm_check_security` for AC_ENF_EXECVE |

### Data-Flow Trace (Level 4)

Level 4 applies to components that render dynamic data. These are BPF kernel programs and C test files, not UI components — data flow is event emission from BPF to ring buffer consumed by tests. The critical flow is:

| Component | Data Variable | Source | Produces Real Data | Status |
|-----------|---------------|--------|--------------------|--------|
| `inject.bpf.h` | deny event | `emit_deny(AC_ENF_INJECT, me, me)` | Caller PID from `cur_pid()`, real kernel state | ✓ FLOWING |
| `execve.bpf.h` | deny event | `emit_deny(AC_ENF_EXECVE, me, me)` | Caller PID from `cur_pid()`, real kernel state | ✓ FLOWING |
| `proc.bpf.h` | deny event | `emit_deny(AC_ENF_PROC, me, ac_protected_root_pid)` | PIDs from kernel state | ✓ FLOWING |
| `tests/inject.cpp` | `ev->enforcer`, `ev->pid` | `sess.next_event()` from ring buffer | Real BPF deny event | ✓ FLOWING (requires Linux kernel for verification) |

### Behavioral Spot-Checks

Step 7b: SKIPPED — BPF programs require kernel execution; no entry point is runnable on macOS. Build system requires Linux BPF toolchain (bpftool). All behavioral checks deferred to Human Verification.

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| REQ-01 | 01-01, 01-02 | inject/mmap enforcer — blocks PROT_EXEC anonymous mmap from within protected subtree | ✓ SATISFIED | `src/bpf/inject.bpf.h` with `SEC("lsm/mmap_file")`, A1 interpretation documented (see REQ-01 note below) |
| REQ-02 | 01-01, 01-03 | execve enforcer using bprm_check_security | ✓ SATISFIED | `src/bpf/execve.bpf.h` with `SEC("lsm/bprm_check_security")`, root exemption, descendants blocked |
| REQ-03 | 01-01, 01-04 | /proc coverage audit + proc enforcer for gaps | ✓ SATISFIED | A3 audit documented in design-decisions.md; proc.bpf.h covers status/cmdline/environ; note: audit is inferred, not empirical |
| REQ-04 | 01-02 | Enum updates for AC_ENF_INJECT, AC_ENF_EXECVE, AC_ENF_PROC | ✓ SATISFIED | ac.h: INJECT=3, EXECVE=4, PROC=5, COUNT=6 with descriptive comments |
| REQ-05 | 01-02 | Tests for inject enforcer | ✓ SATISFIED | `tests/inject.cpp` with attack-succeeds + protected + negative smoke test sections |
| REQ-06 | 01-03 | Tests for execve enforcer | ✓ SATISFIED | `tests/execve.cpp` with attack-succeeds + protected + root-startup-exempt sections |
| REQ-07 | 01-04 | Tests for proc coverage (conditional on REQ-03 finding gaps) | ✓ SATISFIED | `tests/proc.cpp` with 3 TEST_CASEs (status, cmdline, environ) |
| REQ-08 | 01-02, 01-04 | CLI reflects all new enforcers | ✓ SATISFIED | `src/cli/main.c` enforcer_name() returns "inject", "execve", "proc" for new IDs; default returns "?" |
| REQ-09 | 01-04 | docs/testing.md + ac.h comments | ✓ SATISFIED | testing.md documents all 3 new enforcers with hook attribution; ac.h has per-enforcer comments |

**REQ-01 interpretation note:** REQ-01 text says "blocks external processes from creating PROT_EXEC mappings targeting the protected subtree." The A1 design decision (recorded in docs/design-decisions.md) established that an external process cannot directly mmap into another process's address space — that path requires ptrace, which is already blocked by AC_ENF_MEMORY. The remaining injection vector is the game process itself allocating anonymous executable pages. Option-a was accepted at the blocking checkpoint (Task 2 in Plan 01-01). The implementation correctly satisfies the underlying security property (REQ-01 also states "Must not fire on the protected process's own legitimate library loads" — the `file != NULL` exemption handles this precisely). Status: SATISFIED via documented design decision.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `docs/design-decisions.md` | A3 section | A3 results marked "(inferred)" from kernel source, not empirically verified | ⚠️ Warning | proc.bpf.h scope (status/cmdline/environ only) was chosen based on inferred results. If the actual kernel does not gate mem/maps/smaps/auxv via ptrace_access_check for all open paths, there may be uncovered paths. Human verification required. |
| `src/bpf/proc.bpf.h` | (documented in SUMMARY) | No self-exemption for protected process opening /proc/self/ | ⚠️ Warning | Protected process opening /proc/self/status fires AC_ENF_PROC. SUMMARY documents this as acceptable for current test target (flag_secret) which does not self-introspect. Risk materialises for real game binaries using glibc or Go runtime. |

No BLOCKER anti-patterns found. No TODO/FIXME/placeholder markers in any new files. No stub implementations (all new functions have substantive bodies).

### Human Verification Required

#### 1. Linux Build + Full Test Suite

**Test:** On a Linux host with `CONFIG_BPF_LSM=y`, `lsm=...,bpf` in boot args, kernel 5.11+:
```
mise x -- conan install . -s build_type=Debug --build=missing
cmake --preset conan-debug
cmake --build --preset conan-debug --parallel
sudo ctest --preset conan-debug --output-on-failure
```
**Expected:** All tests pass, including the new `[inject]`, `[execve]`, `[proc]` TEST_CASEs. Specifically:
- "inject enforcer blocks anonymous PROT_EXEC mmap" / "attack succeeds" section passes (mmap returns valid ptr without enforcer)
- "inject enforcer blocks anonymous PROT_EXEC mmap" / "protected" section passes (AC_ENF_INJECT event received, mmap returns MAP_FAILED EPERM)
- "inject enforcer: no spurious events during normal session" passes (no false positives)
- "execve enforcer blocks exec from protected subtree descendant" / both sections pass
- "execve enforcer does not block root's own startup exec" passes
- "proc enforcer blocks open of /proc/<pid>/{status,cmdline,environ}" (all three) pass
**Why human:** BPF programs require bpftool + Linux kernel for compilation and loading. `bpf_get_current_task_btf()` (kernel 5.11+), `lsm.s/file_open` sleepable variant, and dentry CO-RE reads cannot be validated statically.

#### 2. A3 Empirical Verification

**Test:** Within the test run above, verify attribution correctness:
- Run proc audit scenario: confirm `open(/proc/<pid>/mem)` is blocked by AC_ENF_MEMORY (not AC_ENF_PROC)
- Run proc audit scenario: confirm `open(/proc/<pid>/maps)` is blocked by AC_ENF_MEMORY (not AC_ENF_PROC)
- Run proc audit scenario: confirm `open(/proc/<pid>/status)` is blocked by AC_ENF_PROC (not AC_ENF_MEMORY)
- Run proc audit scenario: confirm `open(/proc/<pid>/cmdline)` is blocked by AC_ENF_PROC
- Run proc audit scenario: confirm `open(/proc/<pid>/environ)` is blocked by AC_ENF_PROC

**Expected:** Attribution matches the A3 decision table in docs/design-decisions.md.
**Why human:** A3 results are inferred from kernel source analysis. Plan 01-01 SUMMARY explicitly states this. The proc.bpf.h implementation narrows scope to {status,cmdline,environ} — if the inference is wrong for a given kernel version, the scope is incorrect and the full test suite may reveal false attributions or missed paths.

#### 3. proc Self-Introspection False-Positive Assessment

**Test:** If the target game binary is a real binary (not flag_secret stub): run it under `ac` and verify no AC_ENF_PROC events fire during normal startup from the protected process reading its own /proc/self/ files.
**Expected:** Either no false positives, or acceptable false positives with a documented mitigation plan.
**Why human:** proc.bpf.h has no self-exemption (by design, for simplicity). The SUMMARY documents this limitation and states a future plan should add `if (me == ac_protected_root_pid || is_in_protected_subtree(...)) return 0;` if needed. This is only relevant for real game binaries.

### Gaps Summary

No BLOCKER gaps. All 9 must-have truths and all 9 requirements are satisfied by static analysis. The phase goal (adding inject/execve/proc enforcers with tests and documentation) is complete in code.

The `human_needed` status reflects:
1. BPF programs are untestable without a Linux kernel + BPF toolchain (macOS verification environment)
2. A3 audit is inferred, not empirical — the correctness of proc.bpf.h's path selection depends on the actual kernel behavior matching kernel source analysis

These are expected constraints documented from the start (Plan 01-01 SUMMARY, Plan 01-03 SUMMARY, Plan 01-04 SUMMARY all note the macOS/Linux split). They are not defects in the implementation.

---

_Verified: 2026-05-10T00:00:00Z_
_Verifier: Claude (gsd-verifier)_
