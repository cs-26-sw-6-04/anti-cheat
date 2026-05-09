# Phase 1: BPF LSM Gap Closure - Pattern Map

**Mapped:** 2026-05-09
**Files analyzed:** 9 new/modified files
**Analogs found:** 9 / 9

---

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `src/bpf/inject.bpf.h` | BPF enforcer header | event-driven (LSM deny) | `src/bpf/mem.bpf.h` | exact role; different hook |
| `src/bpf/execve.bpf.h` | BPF enforcer header | event-driven (LSM deny) | `src/bpf/mem.bpf.h` | exact role; different hook |
| `src/bpf/proc.bpf.h` | BPF enforcer header (conditional) | event-driven (LSM deny) | `src/bpf/mem.bpf.h` | exact role; different hook |
| `src/bpf/enforcers.bpf.c` | BPF translation unit (include list) | — | `src/bpf/enforcers.bpf.c` itself | self-update |
| `src/shared/ac.h` | Shared enum / API header | — | `src/shared/ac.h` itself | self-update |
| `src/cli/main.c` | CLI display utility | request-response | `src/cli/main.c` itself | self-update |
| `tests/inject.cpp` | Integration test | event-driven | `tests/memory.cpp` + `tests/subtree.cpp` | role-match; harness variant |
| `tests/execve.cpp` | Integration test | event-driven | `tests/subtree.cpp` + `tests/memory.cpp` | role-match; harness variant |
| `tests/proc.cpp` (conditional) | Integration test | event-driven | `tests/memory.cpp` | role-match |
| `tests/support/targets.{hpp,cpp}` | Test target factory | — | existing factories in `targets.cpp` | exact; add new factories |

---

## Pattern Assignments

### `src/bpf/inject.bpf.h` (BPF enforcer, event-driven)

**Analog:** `src/bpf/mem.bpf.h`

**File skeleton pattern** (`mem.bpf.h` lines 1–9):
```c
/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include "common.bpf.h"
```

**Core hook pattern** (`mem.bpf.h` lines 11–27, adapted for `mmap_file`):

`mmap_file` does NOT pass a `struct task_struct *` argument — unlike `ptrace_access_check` which supplies `child` directly. The caller's task struct must be retrieved via `bpf_get_current_task_btf()` (kernel 5.11+; project minimum is 5.10 — see Assumption A5 in RESEARCH.md).

```c
SEC("lsm/mmap_file")
int BPF_PROG(inject_mmap_enforce, struct file *file,
             unsigned long reqprot, unsigned long prot,
             unsigned long flags, int ret) {
  if (ret)                          // ALWAYS first — pass prior LSM deny through
    return ret;

  if (!(prot & PROT_EXEC))          // only care about executable mappings
    return 0;

  if (file != NULL)                 // file-backed = legitimate library load; skip
    return 0;                       // anonymous (file==NULL) = shellcode candidate

  __u32 me = cur_pid();
  struct task_struct *t = bpf_get_current_task_btf();  // NOT from hook args

  if (!is_in_protected_subtree(t))  // domain check: caller must be in subtree
    return 0;

  // NOTE: victim domain for inject is the calling process itself (me == victim)
  // because mmap only maps into the caller's own address space.
  // See RESEARCH.md Open Question A1 for design rationale.
  emit_deny(AC_ENF_INJECT, me, me);
  return -EPERM;
}
```

**Key deltas from `mem.bpf.h` to copy carefully:**

| `mem.bpf.h` pattern | `inject.bpf.h` adaptation |
|--------------------|--------------------------|
| `struct task_struct *child` from hook args | `bpf_get_current_task_btf()` — no task arg in `mmap_file` |
| `__u32 victim = BPF_CORE_READ(child, tgid)` | No separate victim; `me == victim` |
| `is_in_protected_subtree(child)` | `is_in_protected_subtree(t)` (locally retrieved) |
| Hook: `lsm/ptrace_access_check` | Hook: `lsm/mmap_file` |

**Anti-pattern warning:** Do NOT call `bpf_override_return()`. The LSM return value IS the deny. See RESEARCH.md Pitfall 1.

---

### `src/bpf/execve.bpf.h` (BPF enforcer, event-driven)

**Analog:** `src/bpf/mem.bpf.h`

**File skeleton pattern:** identical to `inject.bpf.h` above (same SPDX header, `#pragma once`, `#include "common.bpf.h"`).

**Core hook pattern** (`lsm/bprm_check_security`):

Like `mmap_file`, `bprm_check_security` does not pass a task pointer — `bpf_get_current_task_btf()` is required.

```c
SEC("lsm/bprm_check_security")
int BPF_PROG(execve_enforce, struct linux_binprm *bprm, int ret) {
  if (ret)                          // ALWAYS first
    return ret;

  __u32 me = cur_pid();
  struct task_struct *t = bpf_get_current_task_btf();

  if (!is_in_protected_subtree(t))  // domain check: exec must originate in subtree
    return 0;

  // TODO: first-exec problem — see RESEARCH.md Open Question A2.
  // The game binary itself is exec'd from the subtree after ac_spawn_and_protect
  // attaches. Option (a): fire only on descendants of root, not root itself.
  // DO NOT implement this without resolving A2 with the user.

  emit_deny(AC_ENF_EXECVE, me, me);
  return -EPERM;
}
```

**Key deltas from `mem.bpf.h`:**

| `mem.bpf.h` pattern | `execve.bpf.h` adaptation |
|--------------------|--------------------------|
| Hook: `lsm/ptrace_access_check` | Hook: `lsm/bprm_check_security` |
| `struct task_struct *child` from args | `bpf_get_current_task_btf()` |
| Victim is an external process | Victim is the exec'ing process itself (`me == victim`) |

**Blocked by:** Open Question A2 (first-exec problem). The planner must obtain user input before finalizing the implementation of this file.

---

### `src/bpf/proc.bpf.h` (BPF enforcer, event-driven — conditional on REQ-03 audit)

**Analog:** `src/bpf/mem.bpf.h`

**File skeleton pattern:** identical to above.

**Core hook pattern** (`lsm.s/file_open` — note `.s` = sleepable, required for `bpf_d_path`):

```c
SEC("lsm.s/file_open")           // sleepable: required for bpf_d_path / dentry inspection
int BPF_PROG(proc_enforce, struct file *file, int ret) {
  if (ret)
    return ret;

  // Path inspection strategy: read dentry name components via BPF_CORE_READ.
  // For /proc/<target_pid>/mem the layout is:
  //   file->f_path.dentry->d_name.name         == "mem"
  //   file->f_path.dentry->d_parent->d_name.name == "<target_pid_str>"
  //   file->f_path.dentry->d_parent->d_parent->d_name.name == "proc"
  // WARNING: verify bpf_d_path / bpf_path_d_path availability at build time.
  // See RESEARCH.md Open Question A3 and Pitfall 5.

  // Implementation placeholder — do NOT write this file until REQ-03 audit
  // confirms gaps in ptrace_access_check coverage.
  return 0;
}
```

**Key deltas from `mem.bpf.h`:**

| `mem.bpf.h` pattern | `proc.bpf.h` adaptation |
|--------------------|------------------------|
| Hook: `lsm/ptrace_access_check` | Hook: `lsm.s/file_open` (sleepable variant) |
| Task pointer from hook args | No task arg; use `bpf_get_current_task_btf()` |
| `is_in_protected_subtree(child)` | Path inspection of `file->f_path.dentry` chain |

**Blocked by:** REQ-03 empirical audit (Open Question A3). The planner should make this file conditional.

---

### `src/bpf/enforcers.bpf.c` (BPF single translation unit, include update)

**Analog:** `src/bpf/enforcers.bpf.c` itself

**Full current content** (lines 1–23):
```c
/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Single translation unit that combines every enforcer. Adding a new
 * enforcer: drop a <name>.bpf.h that declares its SEC() programs and include
 * it here. ...
 */

#include "common.bpf.h"

#include "selfprotect.bpf.h"
#include "mem.bpf.h"

char LICENSE[] SEC("license") = "GPL";
```

**Update pattern:** Add includes for new enforcer headers immediately after `mem.bpf.h`, before the `LICENSE` line:
```c
#include "selfprotect.bpf.h"
#include "mem.bpf.h"
#include "inject.bpf.h"     // NEW
#include "execve.bpf.h"     // NEW
/* #include "proc.bpf.h" */ // NEW — conditional on REQ-03 audit
```

The comment block in the file header must be updated to list all new enforcer domains (inject victim = subtree self-mmap; execve victim = subtree self-exec).

**Note:** License must remain `GPL-2.0-only` (line 5). The `#include`d enforcer headers use `LGPL-2.1-only` — this is correct per the existing pattern (`mem.bpf.h` and `selfprotect.bpf.h` are LGPL-2.1-only; the compiled object in `enforcers.bpf.c` is GPL-2.0-only). Do not change either.

---

### `src/shared/ac.h` (enum extension)

**Analog:** `src/shared/ac.h` itself

**Current `ac_enforcer` enum** (lines 24–35):
```c
enum ac_enforcer {
  AC_ENF_SELFPROTECT = 1,
  AC_ENF_MEMORY      = 2,
  AC_ENF__COUNT      = 3,
};
```

**Updated enum pattern** (from RESEARCH.md Code Examples, REQ-04):
```c
enum ac_enforcer {
  AC_ENF_SELFPROTECT = 1,
  AC_ENF_MEMORY      = 2,
  AC_ENF_INJECT      = 3,   /* NEW: lsm/mmap_file + lsm/file_mprotect */
  AC_ENF_EXECVE      = 4,   /* NEW: lsm/bprm_check_security */
  /* AC_ENF_PROC     = 5, */  /* NEW: lsm.s/file_open — conditional on REQ-03 */
  AC_ENF__COUNT      = 5,   /* update to 6 if AC_ENF_PROC is added */
};
```

**Invariant:** `AC_ENF__COUNT` must always equal the next integer after the last defined `AC_ENF_*` ID. Failing to update it breaks any code iterating `[1, AC_ENF__COUNT)`. See RESEARCH.md Pitfall 6.

**Comment to add** above `AC_ENF_INJECT` (following style of the existing MEMORY comment, lines 28–33):
```c
  /* inject enforcer: blocks anonymous PROT_EXEC mmap (shellcode/JIT injection)
   * from within the protected subtree. Uses lsm/mmap_file hook. */
  AC_ENF_INJECT = 3,
  /* execve enforcer: blocks unauthorized exec from within the protected
   * subtree. Uses lsm/bprm_check_security hook. */
  AC_ENF_EXECVE = 4,
```

---

### `src/cli/main.c` (enforcer_name switch update)

**Analog:** `src/cli/main.c` itself

**Current `enforcer_name()` function** (lines 39–48):
```c
static const char *enforcer_name(unsigned int id) {
  switch (id) {
  case AC_ENF_SELFPROTECT:
    return "selfprotect";
  case AC_ENF_MEMORY:
    return "memory";
  default:
    return "?";
  }
}
```

**Updated pattern** (add cases before `default`):
```c
static const char *enforcer_name(unsigned int id) {
  switch (id) {
  case AC_ENF_SELFPROTECT: return "selfprotect";
  case AC_ENF_MEMORY:      return "memory";
  case AC_ENF_INJECT:      return "inject";     /* NEW */
  case AC_ENF_EXECVE:      return "execve";     /* NEW */
  /* case AC_ENF_PROC:     return "proc"; */    /* NEW — conditional */
  default:                 return "?";
  }
}
```

Note: the existing cases use two-statement style (keyword + block); either style is acceptable, but the single-line form above matches RESEARCH.md's example and is more compact. Follow whichever style is already in the file.

---

### `tests/inject.cpp` (integration test, event-driven)

**Primary analog:** `tests/memory.cpp` (run_scenario structure)
**Secondary analog:** `tests/subtree.cpp` lines 79–116 (raw session + run_attacker without run_scenario)

**Critical note (RESEARCH.md Open Question A6):** The standard `run_scenario` harness forks an *external* attacker process. For `inject` (anonymous PROT_EXEC mmap that the enforcer fires on when the *protected process itself* does it), the attack must originate from *inside* the protected subtree. The recommended approach (RESEARCH §A6 option (b)) is new target factories where the `target_fn` itself performs the mmap. See `targets.cpp` pattern below.

**Test structure pattern** (two-section layout from `memory.cpp` lines 24–49, adapted):
```cpp
/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <sys/mman.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "targets.hpp"

using namespace ac;

TEST_CASE("inject enforcer blocks anonymous PROT_EXEC mmap", "[inject][mmap]") {
  // NOTE: attack originates from INSIDE the protected process.
  // Use target factory variant (targets::mmap_exec_self()) rather than
  // run_scenario, because run_scenario's attacker is always external.
  // See RESEARCH.md Open Question A6 and the targets.cpp pattern below.
  SECTION("attack succeeds (no enforcer)") {
    // spawn target that performs the mmap itself; expect mmap succeeds
  }
  SECTION("protected") {
    // spawn same target under session; expect mmap fails (-EPERM) and
    // sess.next_event() returns AC_ENF_INJECT
  }
}
```

**Required imports** (from `memory.cpp` lines 7–20):
```cpp
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include <sys/mman.h>      // mmap, munmap, MAP_ANONYMOUS, PROT_EXEC

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "targets.hpp"

using namespace ac;
```

**Session open pattern** (from `tests/support/ac.cpp` lines 83–107, used directly when not using run_scenario):
```cpp
auto t = targets::mmap_exec_self()();   // new factory — see targets pattern below
auto sess = session::open_or_skip(t.info().root_pid);
// ... target runs its built-in attack ...
sess.poll();
auto ev = sess.next_event();
REQUIRE(ev.has_value());
REQUIRE(ev->enforcer == AC_ENF_INJECT);
```

---

### `tests/execve.cpp` (integration test, event-driven)

**Primary analog:** `tests/subtree.cpp` lines 79–116 (raw session, no run_scenario)
**Secondary analog:** `tests/memory.cpp` (test case structure)

**Blocked by:** Open Question A2 (first-exec problem). Do not finalize this file's implementation until the user resolves A2 (option (a): fire on descendants only, not the root itself).

**Stub structure** (matches header pattern from all existing test files):
```cpp
/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "targets.hpp"

using namespace ac;

TEST_CASE("execve enforcer blocks unauthorized exec from protected subtree",
          "[execve]") {
  // BLOCKED: Resolve RESEARCH.md Open Question A2 (first-exec problem) first.
  // Factory: targets::exec_child() — target_fn forks a grandchild that execs
  // a known binary; the enforcer must fire on the grandchild's exec, not the
  // root's startup exec.
}
```

---

### `tests/proc.cpp` (integration test, event-driven — conditional)

**Analog:** `tests/memory.cpp` (same run_scenario pattern; proc attacks ARE from external process)

**Conditional:** Only create this file if REQ-03 audit confirms `/proc/<pid>/` paths beyond `mem` and `environ` are not covered by `ptrace_access_check`.

**Attack pattern** (closest analog: `memory.cpp` external attacker opening `/proc/<pid>/mem`):
```cpp
TEST_CASE("proc enforcer blocks /proc/<pid>/maps open", "[proc][open]") {
  run_scenario({
      .target = targets::flag_secret(),
      .attack = [](const target_info &info) -> int {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%u/maps", info.pid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) return 1;   // blocked: success for the attacker
        close(fd);
        return 0;
      },
      .expect_enforcer = AC_ENF_PROC,
      .verify_success = [](target &, const attack_result &) {
        // fd open returning >= 0 is the capability under test
      },
  });
}
```

---

### `tests/support/targets.{hpp,cpp}` (new target factories)

**Analog:** existing factories in `tests/support/targets.cpp` and `tests/support/targets.hpp`

**Why modification is needed:** inject and execve tests require attacks that originate from inside the protected process. The solution (RESEARCH §A6 option (b)) is new factories whose `target_fn` itself performs the malicious action.

**Pattern to copy** (from `targets.cpp` `flag_secret()` lines 24–51):

```cpp
// In targets.hpp — add declarations following existing style:
namespace ac::targets {
  target_factory mmap_exec_self();   // NEW: target maps anonymous PROT_EXEC; returns exit 0 on success
  target_factory exec_child();       // NEW: target forks+execs a grandchild binary
} // namespace ac::targets
```

**Factory body pattern** (from `targets.cpp` `flag_secret()` — use `target::spawn()` with a lambda):
```cpp
target_factory mmap_exec_self() {
  return []() {
    auto t = target::spawn([] {
      // Allow sibling attacker to ptrace us (from flag_secret pattern, line 29)
      (void)prctl(PR_SET_PTRACER, static_cast<unsigned long>(-1), 0, 0, 0);

      // Print READY with dummy addr/len so the test harness can parse it
      printf("READY %u 0 0\n", (unsigned)getpid());
      fflush(stdout);

      // Perform the attack from inside the protected process:
      void *p = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
      int result = (p == MAP_FAILED) ? 1 : 0;  // 1 = blocked (desired under enforcer)
      if (p != MAP_FAILED)
        munmap(p, 4096);

      while (getchar() != EOF) {}  // wait for test to signal done (from flag_secret lines 40-42)

      printf("FLAG %s\n", result == 0 ? "mmap_succeeded" : "mmap_blocked");
      fflush(stdout);
      return result;
    });
    t.set_flag("mmap_succeeded");  // expected flag when no enforcer
    t.set_root_pid(t.info().pid);
    return t;
  };
}
```

**READY line parsing:** The test harness (`target.cpp`) parses `"READY <pid> <addr> <len>\n"`. For factories where addr/len are not meaningful, pass `0 0` — the test verifies enforcement via the session event, not via memory read-back.

---

## Shared Patterns

### 1. BPF Enforcer Mandatory Prologue
**Source:** `src/bpf/mem.bpf.h` line 14, `src/bpf/selfprotect.bpf.h` line 13
**Apply to:** ALL new `*.bpf.h` files, as the first statement in every `BPF_PROG` body
```c
if (ret)
  return ret;
```
**Rationale:** BPF LSM chains pass the prior hook's return value as the last argument. Missing this check overwrites a prior `-EPERM` from an earlier hook. See RESEARCH.md Pitfall 2.

### 2. BPF Helper: `cur_pid()`
**Source:** `src/bpf/common.bpf.h` lines 42–44
**Apply to:** All new `*.bpf.h` files
```c
static __always_inline __u32 cur_pid(void) {
  return bpf_get_current_pid_tgid() >> 32;
}
```
This is already in `common.bpf.h` and available to all enforcers via `#include "common.bpf.h"`. Do NOT redefine it.

### 3. BPF Helper: `is_in_protected_subtree()`
**Source:** `src/bpf/common.bpf.h` lines 54–71
**Apply to:** All new `*.bpf.h` files (domain check for subtree membership)
```c
static __always_inline bool is_in_protected_subtree(struct task_struct *t) {
  if (!ac_protected_root_pid)
    return false;
  struct task_struct *cur = t;
#pragma unroll
  for (int i = 0; i < AC_ANCESTOR_WALK_DEPTH; i++) {
    if (!cur) return false;
    __u32 tgid = BPF_CORE_READ(cur, tgid);
    if (tgid == ac_protected_root_pid) return true;
    if (tgid <= 1) return false;
    cur = BPF_CORE_READ(cur, real_parent);
  }
  return false;
}
```
Do NOT hand-roll an ancestor walk. Do NOT iterate all processes.

### 4. BPF Helper: `emit_deny()`
**Source:** `src/bpf/common.bpf.h` lines 73–84
**Apply to:** All new `*.bpf.h` files (event emission)
```c
static __always_inline void emit_deny(__u32 enforcer, __u32 attacker,
                                      __u32 victim) {
  struct ac_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return;
  e->kind = AC_EVENT_DENY;
  e->enforcer = enforcer;
  e->pid = attacker;
  e->target_pid = victim;
  e->denied_errno = -EPERM;
  bpf_ringbuf_submit(e, 0);
}
```
Privacy constraint: events carry only pids and errno. No paths, command lines, or memory content.

### 5. `bpf_get_current_task_btf()` for caller's task struct
**Source:** RESEARCH.md Pattern 2 (verified from kernel 5.11 notes)
**Apply to:** `inject.bpf.h`, `execve.bpf.h`, and `proc.bpf.h` — all hooks that lack a `struct task_struct *` argument
```c
struct task_struct *t = bpf_get_current_task_btf();
```
**Caution (Assumption A5):** `bpf_get_current_task_btf()` is available on kernel 5.11+. Project minimum is 5.10. If running on exactly 5.10, this call fails at the verifier. Fallback: use `cur_pid()` only (pass `me` as both pid and target_pid in `emit_deny`).

### 6. Test Session Open / SKIP Pattern
**Source:** `tests/support/ac.cpp` lines 39–56
**Apply to:** `tests/inject.cpp`, `tests/execve.cpp`, `tests/proc.cpp`
```cpp
auto sess = session::open_or_skip(t.info().root_pid);
```
`open_or_skip()` calls `Catch2::SKIP()` on `EPERM`/`EACCES` (unprivileged environment). All protected-section test cases must go through this function, never `ac_open` directly. The test then drives `sess.poll()` + `sess.next_event()` to check for the deny event.

### 7. SPDX License Headers
**Source:** All existing files
**Apply to:** All new files

BPF headers (`*.bpf.h`) and userspace loader code:
```c
/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
```

BPF translation unit (`enforcers.bpf.c` — already GPL, do not change):
```c
 * SPDX-License-Identifier: GPL-2.0-only
```

C++ test files:
```cpp
/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
```

---

## No Build System Changes Required

The `src/bpf/CMakeLists.txt` does not need modification. The comment in that file (line 23–24) says "Adding a new enforcer: drop a `<name>.bpf.h` that declares its SEC() programs and `#include` it from `enforcers.bpf.c`." The `add_bpf_object(enforcers enforcers.bpf.c ...)` call automatically picks up changes to `enforcers.bpf.c`. No `add_bpf_object` or `add_bpf_skeleton` calls need updating.

The `tests/CMakeLists.txt` uses `file(GLOB AC_TEST_SOURCES CONFIGURE_DEPENDS "*.cpp")` (line 17) — new `tests/*.cpp` files are picked up automatically. No CMake changes needed there either.

---

## Open Design Questions (Planner Must Escalate)

The following questions from RESEARCH.md are NOT resolved in this document and must be presented to the user before the corresponding tasks are written:

| Question | Affects | Resolution Needed Before |
|----------|---------|--------------------------|
| A1: inject victim domain (caller = game itself vs external) | `inject.bpf.h` implementation, `tests/inject.cpp` | Writing inject enforcer task |
| A2: execve first-exec problem (option a/b/c/d) | `execve.bpf.h` implementation, `tests/execve.cpp` | Writing execve enforcer task |
| A3: ptrace_access_check `/proc/<pid>/` coverage gap audit | `proc.bpf.h` (whether to create it), `tests/proc.cpp` | Writing proc enforcer task |
| A6: inject/execve test harness (run_scenario vs factory) | `tests/inject.cpp`, `tests/execve.cpp`, `tests/support/targets.*` | Writing test tasks |

The planner should structure tasks so A1/A2/A3/A6 are user decision points at the start of each affected wave, with the implementation tasks gated on the outcome.

---

## No Analog Found

All files have analogs in the codebase. No files require falling back to RESEARCH.md patterns exclusively.

---

## Metadata

**Analog search scope:** `src/bpf/`, `src/shared/`, `src/cli/`, `tests/`, `tests/support/`
**Files scanned:** 16 source files read in full
**Pattern extraction date:** 2026-05-09
