<!--
SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Scope

This project does **not** try to solve every kind of cheating. Its scope is narrower: protect client integrity on Linux by treating the booted distribution kernel as the trust anchor and treating the rest of the machine as hostile.

## Trusted Base

We trust the Secure Boot validated distribution layer:

- Boot loaders signed by an official Microsoft Secure Boot key.
- The Linux kernel shipped by the distribution.
- Kernel modules shipped by the distribution.

We also trust the statically compiled anti-cheat binaries that we build:

- The loader.
- Its eBPF programs and LSM enforcers.

Everything else is hostile.

## In-Scope Attacker Powers

Assume the attacker has full control of userspace, including `root`, and knows the full source code.

That includes:

- The protected application.
- Files, folders, and local configuration.
- Shared libraries, the dynamic loader, and process environment.
- Normal client-side tampering techniques such as replacement, injection, tracing, patching, hooking, and slowdown or timing manipulation.
- Attempts to fool trust establishment through virtualization, including VMs or virtualized TPM-style signals.

## Security Goal

A successful in-scope attack is one that lets the attacker read or change protected state, or bypass the loader's enforcement, **without first breaking the trusted base above**.

The loader should therefore rely on the trusted kernel layer for enforcement and should avoid inheriting trust from hostile userspace. In practice that means minimizing attacker-controlled dependencies and anchoring policy in eBPF LSM enforcement where possible.

## Out of Scope

Attacks are out of scope here if they require any of the following:

- Replacing or modifying the trusted boot path, for example the Microsoft signing key.
- Breaking Secure Boot, for example replacing the trusted distribution kernel or loading untrusted kernel code.
- Compromising firmware or hardware below the OS.
- Cheating purely through game rules, servers, or real-world coordination.

This scope is intentionally narrower than a commercial end-to-end anti-cheat. The goal is to remove cheap client-side tampering and create a defensible trust framework for a userspace and kernel-space anti-cheat on an otherwise open Linux system.

## Residual Weaknesses

### Loader process death drops enforcement

BPF LSM programs live for as long as the loader holds their `bpf_link` file descriptors. If the loader exits, including a hostile `SIGKILL` from root, the kernel closes those fds during `do_exit`, detaches the programs, and enforcement stops. BPF has no "on unload" hook we could use to react from inside the kernel, and a non-PID-1 process cannot mask `SIGKILL`.

The design closes this by binding the protected process's life to the loader's:

- The protected root is spawned by the loader and sets `PR_SET_PDEATHSIG(SIGKILL)` on itself before it executes any attackable code. When the loader exits for any reason, the kernel atomically delivers `SIGKILL` to the protected root.
- The invariant is therefore: *loader alive ⇒ enforcement active; loader dead ⇒ protected root also dead.* The cheat target is gone at the moment enforcement goes away, so there is nothing interesting left to attack.

Residual micro-race: between the loader's fd-table teardown dropping the BPF links and the protected root actually processing its `SIGKILL`, there is a brief window (microseconds) where enforcement is off but the target is still running. An attacker who can time a syscall into that window could read or write the target's memory. Closing this would require either making the loader unkillable (not possible outside PID 1) or moving enforcement into a kernel module (out of scope per the trusted base).

The protected root sets `PR_SET_CHILD_SUBREAPER` on itself before exec. This keeps orphans of a daemonized intermediate (wineserver's double-forked game process, a `setsid` + double-fork crash-reporter helper) reparented onto the protected root rather than escaping past it; the BPF ancestor walk in `mem.bpf.h` would otherwise treat those processes as external and deny their reads of the game. Descendants are not covered by `PR_SET_PDEATHSIG` and may outlive the protected root; once the root dies the loader tears the session down and they lose enforcement, same as above.

Out-of-band mitigations (server-side liveness checks, service supervision, heartbeat-gated sessions) are expected to detect loader absence; they are orthogonal to the in-kernel protections described here.

### Hostile BPF reads user memory without invoking LSM ptrace hooks

A BPF program loaded by root can call `bpf_copy_from_user_task` to read another task's userspace memory. The helper uses `access_process_vm` and does **not** invoke `security_ptrace_access_check`, so none of our LSM hooks fire. See `tests/ebpf_exfil.cpp`.

Refusing new BPF program loads via `lsm/bpf` and rejecting AC startup when memory-reading program types are already present does not work in practice. systemd ships BPF programs that the check would have to refuse (`restrict_filesystems` LSM, cgroup networking and device filters), breaking startup on any normal distribution. Whitelisting by name or hash does not help: a root attacker can replace the trusted system binaries (e.g., systemd) with versions whose embedded BPF programs perform the read.

The workable direction is bytecode-level analysis of every BPF program at load time and at AC startup. Inspect each program's instructions and BTF for calls to helpers that can read another task's memory (`bpf_copy_from_user_task`, `bpf_probe_read_user_*`, `bpf_copy_from_user_task_str`, and future additions) and refuse any program that uses them against an arbitrary task argument. This is closer to antivirus-style validation than kernel trust: the trust boundary moves from the kernel itself to the kernel plus this validator.

Not implemented in this project.

## Notes

This framing follows common anti-cheat taxonomies that separate client tampering from network, server, and real-world cheating, and matches the industry trend of using prevention-first client integrity plus platform trust anchors such as Secure Boot and TPM-backed signals.

References:

- Haapaniemi, *Cheat detection & prevention methods in video games* (Oulu, 2024): <https://oulurepo.oulu.fi/handle/10024/48840>
- Epic Online Services, Anti-Cheat / Linux support: <https://dev.epicgames.com/docs/epic-online-services/trust-and-safety/anti-cheat-interfaces/anti-cheat-interfaces#linux>
- Moore, *Secure Boot, TPM and Anti-Cheat Engines* (2025): <https://andrewmoore.ca/blog/post/anticheat-secure-boot-tpm/>
