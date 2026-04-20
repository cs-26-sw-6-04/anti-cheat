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

## Notes

This framing follows common anti-cheat taxonomies that separate client tampering from network, server, and real-world cheating, and matches the industry trend of using prevention-first client integrity plus platform trust anchors such as Secure Boot and TPM-backed signals.

References:

- Haapaniemi, *Cheat detection & prevention methods in video games* (Oulu, 2024): <https://oulurepo.oulu.fi/handle/10024/48840>
- Epic Online Services, Anti-Cheat / Linux support: <https://dev.epicgames.com/docs/epic-online-services/trust-and-safety/anti-cheat-interfaces/anti-cheat-interfaces#linux>
- Moore, *Secure Boot, TPM and Anti-Cheat Engines* (2025): <https://andrewmoore.ca/blog/post/anticheat-secure-boot-tpm/>
