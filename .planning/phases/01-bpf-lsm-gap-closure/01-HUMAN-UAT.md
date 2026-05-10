---
status: partial
phase: 01-bpf-lsm-gap-closure
source: [01-VERIFICATION.md]
started: 2026-05-10T00:00:00Z
updated: 2026-05-10T00:00:00Z
---

## Current Test

[awaiting human testing on Linux host]

## Tests

### 1. Linux build + full test suite

expected: `sudo ctest --preset conan-debug --output-on-failure` passes on kernel 5.11+ with CONFIG_BPF_LSM=y. All inject/execve/proc TEST_CASEs must pass — both "attack succeeds (no enforcer)" and "protected" sections.
result: [pending]

### 2. A3 empirical verification

expected: `open(/proc/<pid>/mem)` fires AC_ENF_MEMORY (not AC_ENF_PROC); `open(/proc/<pid>/status)`, `cmdline`, `environ` fire AC_ENF_PROC. Confirms the inferred A3 audit results are correct for the actual kernel version in use.
result: [pending]

### 3. proc self-introspection false-positive check

expected: No AC_ENF_PROC events fire when the protected game process reads its own /proc/self/ files at startup (glibc and Go runtime both read /proc/self/status). proc.bpf.h has no self-exemption; verify this is not a problem in practice.
result: [pending]

## Summary

total: 3
passed: 0
issues: 0
pending: 3
skipped: 0
blocked: 0

## Gaps
