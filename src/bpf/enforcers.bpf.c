/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Single translation unit that combines every enforcer. Adding a new
 * enforcer: drop a <name>.bpf.h that declares its SEC() programs and include
 * it here. BPF cannot cleanly share maps across object files linked with
 * bpftool gen object, so all enforcers live in one TU.
 *
 * Enforcers split by DOMAIN (who the victim is), not by operation kind:
 *   - selfprotect: victim == ac_self_pid (loader itself).
 *   - mem:         victim in the ac_protected_root_pid subtree.
 *   - inject:      caller in ac_protected_root_pid subtree, prot & PROT_EXEC,
 *                  file == NULL (anonymous PROT_EXEC mmap = shellcode injection).
 *   - execve:      caller is descendant (not root) of ac_protected_root_pid;
 *                  blocks exec of attacker-controlled binaries from the subtree.
 * Domains are disjoint (mem explicitly skips ac_self_pid via its walk), so
 * attribution does not depend on BPF LSM chain ordering.
 */

#include "common.bpf.h"

#include "selfprotect.bpf.h"
#include "mem.bpf.h"
#include "inject.bpf.h"
#include "execve.bpf.h"

char LICENSE[] SEC("license") = "GPL";
