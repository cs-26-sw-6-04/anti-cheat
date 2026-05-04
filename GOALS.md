<!--
SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Goals

This is a game protector. Two non-negotiables shape every design decision:

**Performance.** A frame budget is 16 ms. Every hook we add runs in that
budget, on every relevant syscall, on every process on the box. Prefer a
single LSM deny at the kernel decision point over any user-visible or
cross-syscall state machine. Reject attribution granularity that costs extra
programs or maps. Release builds must constant-fold debug-only toggles.

**Privacy.** We observe only what enforcement requires. No process tree,
command line, syscall argument, or memory content is read or logged. Events
carry enforcer id, attacker tgid, victim tgid — nothing else. Ring buffer,
not perf sampling. No telemetry, no aggregation.

## Consequences

- The protected target is anchored in BPF rodata (`ac_self_pid`,
  `ac_protected_root_pid`) at skeleton load — no mutable map a hostile root
  could redirect post-attach. Subtree membership is a bounded
  `task->real_parent` walk, not a per-pid registration call.
- LSM hooks only. No tracepoints, kprobes, or syscall tracking unless an
  enforcement gap leaves no alternative.
- Enforcers split by victim domain, not operation kind. Selfprotect (loader
  pid) and memory (subtree) are disjoint, so attribution does not depend on
  LSM chain ordering. Operations the kernel cannot reliably distinguish at
  one hook (e.g. `process_vm_rw` vs `PTRACE_ATTACH` at `ptrace_access_check`)
  share one enforcer rather than getting dishonest sub-attribution.
- Self-protect always on, compiled in, no runtime disable path.
- Debug-only toggles live in `.bss`/`.data`; Release puts them in `.rodata`
  so the verifier dead-code-eliminates the checks.
