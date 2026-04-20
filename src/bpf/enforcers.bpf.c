/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: MIT
 *
 * Single translation unit that combines every enforcer. Adding a new
 * enforcer: drop a <name>.bpf.h that declares its SEC() programs and include
 * it here. BPF cannot cleanly share maps across object files linked with
 * bpftool gen object, so all enforcers live in one TU.
 *
 * Attach order (more-specific-first): selfprotect → ptrace → memory.
 * LSM chain "deny wins": an earlier -EPERM short-circuits the remaining
 * programs, so overlapping policy bits produce exactly one event.
 */

#include "common.bpf.h"

#include "selfprotect.bpf.h"
#include "ptrace.bpf.h"
#include "mem.bpf.h"

char LICENSE[] SEC("license") = "GPL";
