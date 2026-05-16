/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include "target.hpp"

namespace ac::targets {

/* Child process holds a buffer initialized to a freshly-randomized token (set
 * on the returned target's info.flag), announces its pid + address + size via
 * READY, blocks until stdin EOF, then prints FLAG <value>. info.root_pid
 * equals info.pid; the single-process target is its own subtree root. */
target_factory flag_secret();

/* Two-level target: the immediate child (info.root_pid) is the subtree root;
 * it forks a grandchild that holds the secret and is the attack victim
 * (info.pid). Used to verify that the ancestor walk in BPF actually protects
 * descendants of the declared root, not just the root itself. */
target_factory flag_secret_nested();

/* "Target" is the current process, used by self-protect tests where AC's own
 * pid is the victim. No fork. info.root_pid is 0 so mem/ptrace run with no
 * subtree registered (selfprotect still handles the loader pid via rodata). */
target_factory ac_self();

/* Target performs an anonymous PROT_EXEC mmap from inside the protected
 * process. Used by inject enforcer tests (attack originates inside subtree).
 * SYNCHRONISATION: target_fn reads ONE byte (the "go" signal) from stdin
 * after READY before performing the mmap. Test must call t.release() after
 * session::open_or_skip() to unblock the mmap.
 * "attack succeeds" section: call t.release() without session; mmap returns valid ptr.
 * "protected" section: open session first, then t.release(); mmap returns MAP_FAILED (EPERM). */
target_factory mmap_exec_self();

} // namespace ac::targets
