# Requirements

## REQ-01 — inject/mmap enforcer
Add a BPF LSM enforcer using `file_mmap` (and/or `file_mprotect`) that blocks external processes from creating PROT_EXEC mappings targeting the protected subtree. Must not fire on the protected process's own legitimate library loads. Emit `AC_EVENT_DENY` with `AC_ENF_INJECT`.

## REQ-02 — execve enforcer [COMPLETE — Plan 03]
Add a BPF LSM enforcer using `bprm_check_security` (or `bprm_creds_for_exec`) that detects and blocks unauthorized binary execution attempts originating from within the protected subtree. Emit `AC_EVENT_DENY` with `AC_ENF_EXECVE`.

**Delivered:** `src/bpf/execve.bpf.h` with `SEC("lsm/bprm_check_security")`, root exemption (`me == ac_protected_root_pid`), descendant subtree check, `emit_deny(AC_ENF_EXECVE, me, me)` + return -EPERM. Commit 9349344.

## REQ-03 — openat/proc_mem coverage audit
Determine definitively whether `lsm/ptrace_access_check` already covers `/proc/<pid>/mem`, `/proc/<pid>/maps`, and other sensitive `/proc/<pid>/` paths. Document the finding. If gaps exist, add a `file_open` LSM enforcer covering remaining `/proc/<pid>/` paths. Emit `AC_EVENT_DENY` with `AC_ENF_PROC` if a new enforcer is needed.

## REQ-04 — enum and shared header updates
Update `ac_enforcer` enum in `src/shared/ac.h` with new enforcer IDs (`AC_ENF_INJECT`, `AC_ENF_EXECVE`, and optionally `AC_ENF_PROC`). Maintain the count field (`AC_ENF__COUNT`).

## REQ-05 — tests for inject enforcer
Add test cases in `tests/inject.cpp` following the `run_scenario` pattern:
- Attack succeeds section: mmap PROT_EXEC from attacker → succeeds without enforcer
- Protected section: same attack → blocked, `expect_enforcer = AC_ENF_INJECT`

## REQ-06 — tests for execve enforcer [COMPLETE — Plan 03]
Add test cases in `tests/execve.cpp`:
- Attack succeeds section: exec unauthorized binary from attacker/inside subtree → succeeds without enforcer
- Protected section: same attack → blocked, `expect_enforcer = AC_ENF_EXECVE`

**Delivered:** `tests/execve.cpp` with three sections; `exec_child()` factory in targets.hpp/targets.cpp with go-signal synchronisation. Commit 17cb677.

## REQ-07 — tests for proc coverage (if REQ-03 finds gaps)
Add test cases covering any `/proc/<pid>/` paths not already blocked by the memory enforcer.

## REQ-08 — ac CLI integration
Verify the `ac` CLI (src/cli/) correctly reflects all new enforcers in any output/logging it performs. Update enforcer name mappings if present.

## REQ-09 — documentation
Update `docs/testing.md` to document new enforcer domains and their LSM hook attribution. Update comments in `src/shared/ac.h` to explain new enforcer IDs.
