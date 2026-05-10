---
phase: 01-bpf-lsm-gap-closure
reviewed: 2026-05-10T00:00:00Z
depth: standard
files_reviewed: 15
files_reviewed_list:
  - docs/design-decisions.md
  - docs/testing.md
  - src/bpf/enforcers.bpf.c
  - src/bpf/execve.bpf.h
  - src/bpf/inject.bpf.h
  - src/bpf/proc.bpf.h
  - src/cli/main.c
  - src/shared/ac.h
  - tests/execve.cpp
  - tests/inject.cpp
  - tests/proc.cpp
  - tests/support/target.cpp
  - tests/support/target.hpp
  - tests/support/targets.cpp
  - tests/support/targets.hpp
findings:
  critical: 0
  warning: 0
  info: 1
  total: 1
status: fixed
---

# Phase 01: Code Review Report

**Reviewed:** 2026-05-10
**Depth:** standard
**Files Reviewed:** 15
**Status:** fixed

## Summary

This review covers the three new BPF LSM enforcers (`inject.bpf.h`, `execve.bpf.h`, `proc.bpf.h`),
their integration in `enforcers.bpf.c`, the updated test support infrastructure (`target.cpp`,
`targets.cpp`, `target.hpp`, `targets.hpp`), and the three new test files (`inject.cpp`,
`execve.cpp`, `proc.cpp`), plus `src/cli/main.c` and `src/shared/ac.h`.

The overall structure is sound: the three-hook design maps cleanly onto the threat model, the
synchronisation barrier (`release()` / `getchar()` go-signal) prevents the enforcement-attachment
race in inject and execve tests, and the dentry-walk path match in proc.bpf.h is verifier-friendly
and avoids string operations. Two blockers were found: a kernel compatibility break for the stated
5.10 minimum, and a missing NUL terminator in the proc path matcher that allows 8-character names
prefixed with "cmdline" or "environ" to match falsely.

## Critical Issues

### CR-01: `inject.bpf.h` and `execve.bpf.h` use `bpf_get_current_task_btf()` which requires kernel 5.11+, breaking the stated 5.10 minimum

**File:** `src/bpf/inject.bpf.h:34`, `src/bpf/execve.bpf.h:32`

**Issue:** Both programs call `bpf_get_current_task_btf()` to obtain a pointer to the current
`task_struct` for the ancestor walk. This helper was added in kernel 5.11. `CLAUDE.md` declares
Linux 5.10+ as the project minimum. On a 5.10 kernel the BPF verifier will reject the program at
load time with `unknown func`, making both enforcers completely non-functional. The comment in
`inject.bpf.h` acknowledges the risk but offers no fallback: "On kernel 5.10 (project minimum) the
verifier may reject this; fall back to comparing me against ac_protected_root_pid directly if that
occurs." No such fallback exists in the code.

Note that `mem.bpf.h` avoids this problem entirely: the `ptrace_access_check` LSM hook receives the
`child` task_struct as a direct parameter, so it does not need `bpf_get_current_task_btf()` and
works on 5.10.

**Fix:** Either raise the minimum to 5.11 (and update `CLAUDE.md` accordingly), or implement the
documented fallback. For `inject.bpf.h` the fallback is trivial because the caller is always the
protected process itself: if `bpf_get_current_task_btf()` is unavailable, compare `me` directly
against `ac_protected_root_pid` (catches only the root, not its descendants; acceptable for inject
since the root is the primary attack surface here). For `execve.bpf.h` the descendant-check
requires the walk, so the practical fix is to raise the minimum to 5.11.

```c
/* inject.bpf.h -- minimal 5.10-compatible fallback (root-only) */
__u32 me = cur_pid();
if (!ac_protected_root_pid || me != ac_protected_root_pid)
    return 0;
```

For the full ancestor walk on 5.10, `bpf_get_current_task()` (available since 4.x) returns an
`unsigned long`, which must then be cast and accessed via `bpf_probe_read_kernel()` rather than
CO-RE field reads — a non-trivial change. Raising the minimum to 5.11 is the cleaner path.

---

### CR-02: `proc.bpf.h` `is_uncovered_proc_file()` missing NUL terminator check for `cmdline` and `environ`, causing false-positive matches on 8-character names

**File:** `src/bpf/proc.bpf.h:50-60`

**Issue:** The 8-byte buffer `name[8]` receives the dentry filename via `bpf_core_read_str(name,
sizeof(name), ...)`. `bpf_core_read_str` always NUL-terminates and copies at most `bufsz` bytes
including the terminator, so for a string longer than 7 characters the buffer holds the first 7
characters plus a forced NUL at `name[7]`.

The `status` check correctly verifies `name[6] == '\0'` (status is 6 chars; the NUL lands at
index 6). But the `cmdline` (7 chars) and `environ` (7 chars) checks verify only indices 0–6 and
do not check `name[7] == '\0'`:

```c
/* "cmdline" c-m-d-l-i-n-e-\0 */
if (name[0] == 'c' && name[1] == 'm' && name[2] == 'd' &&
    name[3] == 'l' && name[4] == 'i' && name[5] == 'n' &&
    name[6] == 'e')           /* <-- name[7] not checked */
  return 1;
```

A dentry whose name starts with the 7-character sequence `c-m-d-l-i-n-e` (e.g., a hypothetical
`cmdlinex`) would be truncated to `cmdline\0` in the 8-byte buffer and incorrectly match. While no
such file exists under `/proc/<pid>/` today, this is a logic error: the length of the matched
filename is not fully validated.

**Fix:** Add a NUL check at index 7 for both:

```c
/* "cmdline" c-m-d-l-i-n-e-\0 */
if (name[0] == 'c' && name[1] == 'm' && name[2] == 'd' &&
    name[3] == 'l' && name[4] == 'i' && name[5] == 'n' &&
    name[6] == 'e' && name[7] == '\0')
  return 1;

/* "environ" e-n-v-i-r-o-n-\0 */
if (name[0] == 'e' && name[1] == 'n' && name[2] == 'v' &&
    name[3] == 'i' && name[4] == 'r' && name[5] == 'o' &&
    name[6] == 'n' && name[7] == '\0')
  return 1;
```

## Warnings

### WR-01: `proc.bpf.h` fails open when `bpf_core_read_str` or `BPF_CORE_READ` returns an error, allowing an attacker to pass silently

**File:** `src/bpf/proc.bpf.h:78-116`

**Issue:** If `BPF_CORE_READ(file, f_path.dentry)` or any subsequent `bpf_core_read_str` call
fails (e.g., due to a transient kernel issue), the comparison values remain zero-initialised and all
checks fail, returning 0 — the attacker is allowed through with no event emitted. This fail-open
behavior means a kernel memory pressure event or a CO-RE relocation miss silently disables
enforcement for the duration of that call. The same pattern applies to `inject.bpf.h` and
`execve.bpf.h` if `bpf_get_current_task_btf()` returns NULL (though that case IS handled safely by
the NULL check in `is_in_protected_subtree`).

The security impact is low in practice because these reads operate on kernel-owned structures that
should always be accessible from an LSM hook context, but the behavior is not visible to the
operator (no event, no counter increment).

**Fix:** There is no easy way to report a "read failed" condition from BPF to userspace without
adding a dedicated error counter map. A minimum mitigation is a code comment documenting that
`bpf_core_read_str` failure results in fail-open. A more robust approach adds a per-enforcer
dropped-event counter map incremented on read failure.

---

### WR-02: `target.cpp` `release()` silently ignores `write()` failure, leaving child blocked indefinitely

**File:** `tests/support/target.cpp:124`

**Issue:** `release()` writes the go-signal byte with `(void)write(stdin_fd_, &go, 1)`. If `write`
fails (e.g., the child has already exited and closed the read end of the pipe, producing `EPIPE`),
the failure is discarded. The child never receives the go-signal and blocks indefinitely in its
`getchar()` call. The subsequent `stop()` call then deadlocks at `fgets()` waiting for the `FLAG`
line that the child will never print, hanging the test forever.

**Fix:** Check the return value and throw (or FAIL) if the write fails:

```cpp
void target::release() {
  if (stdin_fd_ >= 0) {
    char go = '\n';
    ssize_t n = write(stdin_fd_, &go, 1);
    if (n != 1) {
      /* Child already died or pipe broken; stop() will reap it. */
      close(stdin_fd_);
      stdin_fd_ = -1;
    }
  }
}
```

---

### WR-03: `inject.cpp` smoke test comment is factually incorrect — `flag_secret` target is forked (not exec'd), so ld.so never runs in the child

**File:** `tests/inject.cpp:62-77`

**Issue:** The smoke test comment states:

> "The flag_secret target process loads shared libraries during its own startup via exec+ld.so. If
> the `file != NULL` exemption in inject.bpf.h is correct, no AC_ENF_INJECT event fires."

`target::spawn()` uses plain `fork()` without `exec`. The child inherits the parent's already-mapped
address space; ld.so does not run in the child. No file-backed `PROT_EXEC` mappings occur in the
`flag_secret` child process at all. The smoke test trivially passes because there is simply nothing
to trigger the enforcer, not because the `file != NULL` exemption works correctly. The exemption is
not actually exercised by this test.

**Fix:** Replace the misleading comment with an accurate one. If coverage of the `file != NULL`
exemption is desired, a dedicated negative test must use a target that actually execs a binary (e.g.,
a variant of the `exec_child` factory that installs an enforcer and verifies no `INJECT` event fires
when the binary's `.so` dependencies are loaded by ld.so).

---

### WR-04: `execve.cpp` negative test incorrectly asserts it covers the root's own startup exec exemption

**File:** `tests/execve.cpp:60-79`

**Issue:** The test "execve enforcer does not block root's own startup exec" uses `flag_secret()`
as the target and claims:

> "it was spawned via fork+exec internally (exec_child in src/cli). Any exec that fired during
> spawn_and_protect must not be AC_ENF_EXECVE from the root."

This is wrong in the test context. `target::spawn()` uses plain `fork()` — not `exec`. The
`flag_secret` child never calls `exec` after the session is attached. The test therefore does not
exercise the root exemption (`me == ac_protected_root_pid`) in `execve.bpf.h` at all. The negative
test passes vacuously.

The root exemption path in `execve.bpf.h` remains untested. An attacker-controlled binary could
discover the exemption is missing (e.g., if BPF rodata is corrupted post-load) and exploit the fact
that this case has no test coverage.

**Fix:** Correct the comment to state that the test verifies no spurious `EXECVE` events fire when
the child does no exec operations. To actually cover the root exemption, create a new factory that
has the protected root itself call `execvp` and assert no `AC_ENF_EXECVE` event fires for that
process.

---

### WR-05: `src/cli/main.c` privilege drop does not call `setgroups()` — relies on an unverified deployment assumption

**File:** `src/cli/main.c:25-36`

**Issue:** `exec_child()` calls `setuid(c->real_uid)` to drop root privileges before `execvp`. The
comment documents the assumption: "We never elevated egid or groups (no setgid bit, no setcap +s)
so they already match the caller." This assumption is not verified at runtime. If the `ac` binary
were accidentally installed with a `setgid` bit (e.g., `chmod g+s`) or had group-based capabilities
applied, supplementary group privileges would persist in the child process after `setuid`, even
though root's UID was dropped. The game binary would then run with unintended group access.

**Fix:** Add a defensive `setgroups(0, NULL)` (or `setgroups(1, &real_gid)`) call before
`execvp` to explicitly clear supplementary groups, regardless of deployment assumptions:

```c
if (setuid(c->real_uid) != 0) { ... }
/* Defensively clear supplementary groups regardless of setgid bit or capabilities. */
if (setgroups(0, NULL) != 0) {
    fprintf(stderr, "ac: setgroups: %s\n", strerror(errno));
    return 126;
}
execvp(c->argv[0], c->argv);
```

Note: `setgroups` requires `#include <grp.h>`.

## Info

### IN-01: `src/shared/ac.h` defines `AC_ENF__COUNT` but it is never referenced in any source file

**File:** `src/shared/ac.h:46`

**Issue:** `AC_ENF__COUNT = 6` is defined as a sentinel for the enum but is not used anywhere in
the codebase (not in BPF programs, not in the CLI, not in tests). Unreferenced sentinel values in
enums are harmless but add maintenance cost: if a new enforcer is added and `AC_ENF__COUNT` is not
updated, nothing will catch the stale value.

**Fix:** Either use `AC_ENF__COUNT` as an array size bound somewhere (e.g., a lookup table for
enforcer names), or add a comment explaining it is reserved for future use. If it is not needed,
remove it.

---

_Reviewed: 2026-05-10_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
