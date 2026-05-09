# Phase 01: BPF LSM Gap Closure - Research

**Researched:** 2026-05-09
**Domain:** Linux BPF LSM (BPF_PROG_TYPE_LSM) — inject/mmap, execve, and /proc path coverage
**Confidence:** MEDIUM — hook signatures confirmed from kernel source; domain split for inject and execve enforcers has unresolved design ambiguities flagged as Open Questions

---

## Summary

The current `src/` codebase implements two enforcers (`AC_ENF_SELFPROTECT` and `AC_ENF_MEMORY`) using a single `lsm/ptrace_access_check` hook. Both live in `src/bpf/selfprotect.bpf.h` and `src/bpf/mem.bpf.h`, and are compiled into a single BPF translation unit (`enforcers.bpf.c`). The session API (`ac_open`, `ac_spawn_and_protect`, `ac_poll`, `ac_next_event`) in `src/loader/ac.c` loads and manages the skeleton, burning `ac_self_pid` and `ac_protected_root_pid` into rodata before `enforcers_bpf__load()`. Tests use Catch2 3.11.0 via Conan, with a `run_scenario` harness in `tests/support/`.

Phase 1 adds three missing enforcer domains: (1) `AC_ENF_INJECT` using `lsm/mmap_file` (and optionally `lsm/file_mprotect`) to detect unauthorized PROT_EXEC mappings in the protected subtree; (2) `AC_ENF_EXECVE` using `lsm/bprm_check_security` to detect unauthorized exec from within the protected subtree; (3) optionally `AC_ENF_PROC` using `lsm/file_open` to extend `/proc/<pid>/` path coverage where `ptrace_access_check` does not reach. Each enforcer follows the existing `mem.bpf.h` structural pattern exactly.

Two design ambiguities are not resolvable by research alone: the exact victim-domain interpretation for `inject` (who fires on whom) and the first-exec problem for `execve` (the game binary itself is exec'd after `ac_spawn_and_protect` runs but before the child exits). These are flagged as Open Questions; the planner must obtain user input before fixing the implementation path.

**Primary recommendation:** Add `inject.bpf.h` (`lsm/mmap_file`), `execve.bpf.h` (`lsm/bprm_check_security`), and conditionally `proc.bpf.h` (`lsm/file_open`) under `src/bpf/`, include them in `enforcers.bpf.c`, add enum entries to `src/shared/ac.h`, add corresponding test files, and update `src/cli/main.c`'s `enforcer_name()` switch and `docs/testing.md`.

---

## Project Constraints (from CLAUDE.md and STATE.md)

> IMPORTANT: CLAUDE.md describes the OLD `source/` architecture (separate enforcer/server/client/adversary binaries, tracepoints, mTLS, bpf_override_return for blocking). That code path is empty — `source/` has no files. The authoritative current design is in STATE.md, GOALS.md, SCOPE.md, and the `src/` codebase. The constraints below are derived from the active architecture.

### Active Architecture Invariants (from STATE.md + GOALS.md)

- **LSM hooks only.** No tracepoints, kprobes, or syscall tracking.
- **Blocking via `return -EPERM`** from the LSM hook, not `bpf_override_return`. The LSM hook return value IS the deny — no override syscall needed.
- **Single BPF translation unit.** All enforcers compiled from `enforcers.bpf.c` which `#include`s per-enforcer headers. Adding an enforcer = add `<name>.bpf.h` + include it there.
- **No central on/off toggle.** Each enforcer's rodata-anchored domain check is its only gate. No per-enforcer enable bit.
- **Enforcers split by victim domain, not operation kind.** `selfprotect` and `memory` are disjoint (loader pid vs. subtree). New enforcers must also have disjoint or compatible victim domains.
- **Privacy constraint.** Events carry enforcer id, attacker tgid, victim tgid, and denied_errno. No syscall args, command lines, file paths, or memory content logged in events.
- **rodata-pinned identity.** `ac_self_pid` and `ac_protected_root_pid` are burned in before `skel__load()`. All domain checks use these. No mutable maps for identity.
- **C11, no extensions.** All userspace code is C11. BPF code uses clang `-target bpf` with CO-RE via `vmlinux.h`.
- **Catch2 3.11.0 test framework.** Installed via Conan. Tests in `tests/*.cpp`. Single `ac_tests` executable, CTest runs serially. New enforcer = new `tests/<name>.cpp`.
- **GPL-2.0-only** for BPF programs; **LGPL-2.1-only** for loader and BPF headers (matching existing license blocks).

### CLAUDE.md Directives That Do NOT Apply (stale — old architecture)

The following directives in CLAUDE.md describe the `source/` architecture, not `src/`:
- `bpf_override_return()` for blocking — use `return -EPERM` at LSM hook instead
- `BPF_MAP_TYPE_ARRAY` + `target_pid_map` — replaced by rodata (`ac_protected_root_pid`)
- `BPF_MAP_TYPE_RINGBUF` + `MSG_DETECTION` protocol — replaced by session ring buffer + `ac_event`
- Whitelist via `BPF_MAP_TYPE_HASH` keyed by PID — no whitelist in current architecture
- `add_bpf_object` / `add_bpf_skeleton` CMake patterns — now uses `BpfCompile.cmake` module
- mTLS, server, heartbeat, `MSG_BLOCK`/`MSG_INTERRUPT` — not part of current `src/` design

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-01 | inject/mmap enforcer using `file_mmap` (and/or `file_mprotect`) to block PROT_EXEC mappings; emit `AC_EVENT_DENY` with `AC_ENF_INJECT` | Hook: `lsm/mmap_file`; sig verified from `lsm_hook_defs.h`; victim domain ambiguity flagged as A1 |
| REQ-02 | execve enforcer using `bprm_check_security` to block unauthorized exec from within protected subtree; emit `AC_EVENT_DENY` with `AC_ENF_EXECVE` | Hook: `lsm/bprm_check_security`; sig verified; first-exec problem flagged as A2 |
| REQ-03 | Audit whether `lsm/ptrace_access_check` already covers `/proc/<pid>/mem`, `/proc/<pid>/maps`, etc.; add `file_open` enforcer if gaps exist | Hook: `lsm/file_open`; `bpf_d_path` (or `bpf_path_d_path` kfunc) needed for path inspection; coverage audit must be done empirically |
| REQ-04 | Update `ac_enforcer` enum in `src/shared/ac.h` with `AC_ENF_INJECT`, `AC_ENF_EXECVE`, optionally `AC_ENF_PROC`; maintain `AC_ENF__COUNT` | Straightforward enum extension; see code example below |
| REQ-05 | Tests for inject enforcer in `tests/inject.cpp` following `run_scenario` pattern | Pattern is fully understood from existing test files |
| REQ-06 | Tests for execve enforcer in `tests/execve.cpp` | Depends on resolving A2 (first-exec problem) before test can be written |
| REQ-07 | Tests for proc coverage (if REQ-03 finds gaps) in appropriate test file | Conditional on REQ-03 audit result |
| REQ-08 | Verify `ac` CLI's `enforcer_name()` in `src/cli/main.c` reflects new enforcers | Identified switch statement location; straightforward update |
| REQ-09 | Update `docs/testing.md` and comments in `src/shared/ac.h` | Documentation task; no research ambiguity |
</phase_requirements>

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| PROT_EXEC mmap detection | BPF kernel (`lsm/mmap_file`) | Userspace (via ring buffer event) | Must fire at kernel decision point before mapping is created |
| PROT_EXEC mprotect detection | BPF kernel (`lsm/file_mprotect`) | Userspace (via ring buffer event) | Existing `file_mprotect` hook covers mprotect path |
| Exec detection | BPF kernel (`lsm/bprm_check_security`) | Userspace (via ring buffer event) | Fires before binary executes; can return -EPERM to prevent |
| /proc path coverage | BPF kernel (`lsm/file_open`) | Userspace (via ring buffer event) | `ptrace_access_check` may not catch all `/proc/<pid>/` paths; `file_open` fires at VFS open |
| Enforcer domain identity | BPF rodata (`ac_protected_root_pid`) | — | Immutable post-load; hostile root cannot redirect |
| Event delivery | BPF ring buffer | Userspace (`ac_poll`/`ac_next_event`) | Already exists; new enforcers reuse same `events` map |
| CLI display | Userspace (`src/cli/main.c`) | — | `enforcer_name()` switch updated for new IDs |
| Test harness | C++ (`tests/`) | — | Catch2 `run_scenario` pattern; new `.cpp` per enforcer |

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| libbpf | system (pkg-config) | BPF skeleton loading, ring buffer, CO-RE | Project already uses it; CMakeLists.txt finds via PkgConfig |
| clang (`-target bpf`) | system | BPF object compilation | Existing build system |
| bpftool | system | Skeleton header generation | Existing build system |
| vmlinux.h | `/sys/kernel/btf/vmlinux` | CO-RE type definitions | Already used in `common.bpf.h` |
| Catch2 | 3.11.0 (Conan) | Test framework | Already used; version locked in `conanfile.py` |

[VERIFIED: conanfile.py] [VERIFIED: src/bpf/CMakeLists.txt]

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `bpf_path_d_path` kfunc | kernel 5.15+ | Resolve `struct file *` to path string in BPF LSM | REQ-03 `/proc` path filter if audit shows gap |
| `bpf_d_path` helper (legacy) | kernel 5.9+ | Resolve path string in sleepable LSM hooks | Fallback if kfunc not available; `file_open` is sleepable |

[ASSUMED] `bpf_d_path` is callable from `lsm/file_open` because `file_open` is in the sleepable LSM hook set. The newer `bpf_path_d_path` kfunc (KF_TRUSTED_ARGS) is the preferred approach on kernels that have it. Verify at build time — the verifier will reject the program if the hook does not permit the helper/kfunc.

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `lsm/mmap_file` | `lsm/file_mprotect` | mprotect enforcer fires after initial mmap; need both to close the gap |
| `lsm/bprm_check_security` | `lsm/bprm_creds_for_exec` | creds_for_exec is called first, before the binary handler search; either can block, but bprm_check_security has reliable filename access |
| `bpf_path_d_path` kfunc | parsing `file->f_path.dentry->d_name.name` | dname is only the final component, not the full path; for `/proc/<pid>/mem`, need the parent's dname too (manageable: check dname == "mem" AND grandparent dname == target_pid_str) |

---

## Architecture Patterns

### System Architecture Diagram

```
[Protected subtree (game process)]
        |
        | (exec → bprm_check_security fires)
        | (mmap PROT_EXEC → mmap_file fires in caller's context)
        |
[Kernel BPF LSM chain]
   lsm/ptrace_access_check  ← already: selfprotect + memory enforcers
   lsm/mmap_file            ← NEW: inject enforcer
   lsm/file_mprotect        ← NEW: inject enforcer (mprotect path)
   lsm/bprm_check_security  ← NEW: execve enforcer
   lsm/file_open            ← NEW (if needed): proc enforcer
        |
        | (emit_deny → ring buffer → ac_poll → ac_next_event)
        |
[Loader (ac_session)]
   ring buffer drain → ac_event{kind, enforcer, pid, target_pid, denied_errno}
        |
        | (CLI prints deny line)
        |
[User / ac CLI]
```

### Recommended Project Structure (additions only)

```
src/bpf/
├── common.bpf.h       # unchanged — is_in_protected_subtree, emit_deny, cur_pid
├── selfprotect.bpf.h  # unchanged
├── mem.bpf.h          # unchanged
├── inject.bpf.h       # NEW — lsm/mmap_file + lsm/file_mprotect
├── execve.bpf.h       # NEW — lsm/bprm_check_security
├── proc.bpf.h         # NEW (conditional) — lsm/file_open
└── enforcers.bpf.c    # add #include "inject.bpf.h" etc.

src/shared/ac.h        # add AC_ENF_INJECT, AC_ENF_EXECVE, AC_ENF_PROC, bump AC_ENF__COUNT
src/cli/main.c         # add cases to enforcer_name()

tests/
├── inject.cpp         # NEW
├── execve.cpp         # NEW
└── proc.cpp           # NEW (conditional)
```

### Pattern 1: Existing Enforcer Shape (from `mem.bpf.h`)

Every new enforcer MUST follow this shape exactly. [VERIFIED: src/bpf/mem.bpf.h]

```c
// Source: src/bpf/mem.bpf.h (existing enforcer as template)
SEC("lsm/ptrace_access_check")
int BPF_PROG(mem_enforce, struct task_struct *child, unsigned int mode, int ret) {
  if (ret)               // 1. pass-through if prior LSM already denied
    return ret;

  __u32 me = cur_pid();  // 2. early-out for self
  __u32 victim = BPF_CORE_READ(child, tgid);
  if (me == victim)
    return 0;

  if (!is_in_protected_subtree(child))  // 3. domain check
    return 0;

  emit_deny(AC_ENF_MEMORY, me, victim); // 4. emit ring buffer event
  return -EPERM;                        // 5. deny
}
```

### Pattern 2: inject enforcer (`lsm/mmap_file`)

Hook fires in the context of the calling process (the one invoking mmap). The `file` parameter is NULL for anonymous mappings.

```c
// Source: lsm_hook_defs.h [VERIFIED] + mem.bpf.h pattern [VERIFIED]
SEC("lsm/mmap_file")
int BPF_PROG(inject_mmap_enforce, struct file *file,
             unsigned long reqprot, unsigned long prot,
             unsigned long flags, int ret) {
  if (ret)
    return ret;

  // Only care about PROT_EXEC mappings
  if (!(prot & PROT_EXEC))
    return 0;

  // file == NULL for anonymous mappings (MAP_ANONYMOUS). File-backed mappings
  // — .so files loaded by ld.so at game startup — have file != NULL. Filtering
  // them here means legitimate library loads never trigger the enforcer; no
  // "skip-during-startup" logic is needed elsewhere.
  if (file != NULL)
    return 0;

  __u32 me = cur_pid();
  struct task_struct *t = bpf_get_current_task_btf();

  // Domain check: caller must be in the protected subtree
  // (inject = game maps exec code into itself; external caller
  //  cannot mmap into another process's address space)
  if (!is_in_protected_subtree(t))
    return 0;

  // The victim IS the calling process (the game process mapping exec code)
  emit_deny(AC_ENF_INJECT, me, me);
  return -EPERM;
}
```

Note: `bpf_get_current_task_btf()` (available kernel 5.11+) returns a fully-typed `struct task_struct *` pointer directly — no cast required. [VERIFIED: kernel 5.11 release notes / libbpf CO-RE docs] This is preferred over `bpf_get_current_task()` which returns an opaque `void *` requiring an unsafe cast. The `file == NULL` filter ensures file-backed PROT_EXEC mappings (normal library loads) pass through unblocked.

### Pattern 3: execve enforcer (`lsm/bprm_check_security`)

Hook fires in the context of the process calling exec. The `bprm->file` carries the file being executed.

```c
// Source: kernel core-api/kernel-api.html [CITED] + dawidmacek.com/posts/2025/ebpf-lsm-synchronous-execution-prevention/ [CITED]
SEC("lsm/bprm_check_security")
int BPF_PROG(execve_enforce, struct linux_binprm *bprm, int ret) {
  if (ret)
    return ret;

  __u32 me = cur_pid();
  struct task_struct *t = bpf_get_current_task_btf();

  if (!is_in_protected_subtree(t))
    return 0;

  // TODO: first-exec problem — see Open Questions A2
  // The game binary itself is exec'd from within the protected subtree
  // after ac_spawn_and_protect attaches. Blindly denying all execs from
  // the subtree blocks the game startup.

  emit_deny(AC_ENF_EXECVE, me, me);
  return -EPERM;
}
```

### Pattern 4: proc enforcer (`lsm/file_open`)

Hook fires when any file is opened. Path resolution via `bpf_path_d_path` kfunc (preferred) or `bpf_d_path` (legacy). The `/proc/<pid>/mem` path has the form: grandparent = "proc", parent = "<target_pid>", dname = "mem".

```c
// Source: kernel-api.html [CITED: docs.kernel.org] + search findings [VERIFIED: file_open is in sleepable_lsm_hooks]
// WARNING: bpf_d_path / bpf_path_d_path availability must be verified
// at build time — verifier rejects if hook does not permit it.
SEC("lsm.s/file_open")   // .s = sleepable; required for bpf_d_path
int BPF_PROG(proc_enforce, struct file *file, int ret) {
  if (ret)
    return ret;

  // Read dentry name components to check /proc/<pid>/<file>
  // (abbreviated — actual implementation needs BPF_CORE_READ chain)
  struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
  struct dentry *parent = BPF_CORE_READ(de, d_parent);
  // Check parent name == target_pid_str (requires string comparison in BPF)
  // Check grandparent name == "proc"

  // Emit deny if path matches /proc/<ac_protected_root_pid>/...
  return 0; // placeholder — see Open Question A3
}
```

### Anti-Patterns to Avoid

- **Using `bpf_override_return`:** That is the tracepoint/kprobe pattern from the old `source/` architecture. LSM hooks deny by returning a non-zero errno directly.
- **A global on/off bit per enforcer:** Contradicts GOALS.md. No `volatile const bool inject_enabled` rodata.
- **Multiple BPF translation units:** All enforcers must stay in `enforcers.bpf.c` (single TU) to share the `events` ring buffer and `ac_self_pid`/`ac_protected_root_pid` rodata.
- **Logging path strings or filenames in events:** Violates the privacy constraint. `ac_event` carries only pids and errno, never path data.
- **Using `BPF_MAP_TYPE_HASH` for a PID whitelist:** The current architecture has no whitelist. The old CLAUDE.md whitelist design is from the abandoned `source/` architecture.
- **Calling non-reentrant helpers from non-sleepable hooks:** `bpf_d_path` requires the hook to be declared `SEC("lsm.s/...")` (sleepable). Using it from a non-sleepable hook results in verifier rejection.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Ancestor subtree check | Custom PID walk | `is_in_protected_subtree()` in `common.bpf.h` | Already implemented; proven; verifier-safe bounded loop |
| Event emission | Direct ring buffer writes | `emit_deny()` in `common.bpf.h` | Handles reservation failure; consistent event format |
| Skeleton loading | Manual BPF syscalls | `enforcers_bpf__open()` / `__load()` / `__attach()` | Generated by bpftool; already in `ac.c` |
| Path string comparison | Byte-by-byte loop | `bpf_path_d_path` kfunc + dentry name fields via `BPF_CORE_READ` | Verifier-safe; no unbounded memory access |
| Test session management | Direct `ac_open` calls | `session::open_or_skip()` + `run_scenario()` | Handles privilege skip, drain, attribution check |

**Key insight:** The BPF layer is deliberately minimal — enforce or pass. All policy (what is the subtree, what is the self-pid) is resolved by immutable rodata. New enforcers must not introduce their own identity state.

---

## Common Pitfalls

### Pitfall 1: CLAUDE.md describes the wrong architecture
**What goes wrong:** Planner reads CLAUDE.md's "use bpf_override_return" or "add entries to target_pid_map" and implements those patterns.
**Why it happens:** CLAUDE.md was written for the `source/` architecture and has not been updated.
**How to avoid:** STATE.md + GOALS.md + SCOPE.md are authoritative. All code references should be to `src/`, not `source/`.
**Warning signs:** Any task that mentions `bpf_override_return`, `MSG_DETECTION`, `MSG_BLOCK`, or a whitelist BPF map.

### Pitfall 2: Returning -EPERM from a non-first-in-chain hook without checking `ret`
**What goes wrong:** Overwriting a prior -EPERM with a different negative value, or missing a prior non-zero return from a previous LSM program in the chain.
**Why it happens:** BPF LSM chaining passes the prior return value as the last argument.
**How to avoid:** First line of every BPF_PROG body is `if (ret) return ret;` — copy from `mem.bpf.h` exactly. [VERIFIED: src/bpf/mem.bpf.h, src/bpf/selfprotect.bpf.h]

### Pitfall 3: mmap_file fires for the calling process, not the target
**What goes wrong:** Treating `mmap_file` as if it can detect an external process mapping into the game's address space. It cannot — mmap only maps into the caller's own address space.
**Why it happens:** The CLAUDE.md attack table says "mmap with PROT_EXEC from an external process" which is ambiguous about who the caller is.
**How to avoid:** `mmap_file` detects the *game process itself* mapping executable code (self-injection). External injection via ptrace+poketext is covered by `ptrace_access_check` (already implemented). If the intent is "no external process can inject a shared library into the game", that path is via ptrace and already blocked. See Open Questions A1.
**Warning signs:** Any attempt to look up a "target task" from `mmap_file` — there is no such argument.

### Pitfall 4: execve enforcer blocks the game's own startup
**What goes wrong:** `bprm_check_security` fires when the game process (or its children) exec — which includes the initial game binary launch.
**Why it happens:** `ac_spawn_and_protect` attaches BPF *before* releasing the child to exec. So the first exec the child does is the legitimate game binary, and the enforcer fires on it.
**How to avoid:** Resolve Open Question A2 before implementing. Options include: (a) one-shot bypass rodata, (b) attach after first exec, (c) only fire on exec from *descendants* of root, not root itself.
**Warning signs:** Test "execve enforcer protected" section immediately returns -EPERM when trying to start the test target.

### Pitfall 5: `bpf_d_path` used from a non-sleepable hook
**What goes wrong:** Verifier rejects the BPF program with "helper not supported in this context."
**Why it happens:** `bpf_d_path` is only available to sleepable LSM hooks (`SEC("lsm.s/...")`).
**How to avoid:** Declare `proc.bpf.h`'s hook as `SEC("lsm.s/file_open")` not `SEC("lsm/file_open")`. Alternatively, read dentry name fields directly with `BPF_CORE_READ` without `bpf_d_path` (possible for structured paths like `/proc/<pid>/mem` where the depth is fixed).
**Warning signs:** Load error from `enforcers_bpf__load()` referencing "sleepable" or "helper not allowed."

### Pitfall 6: AC_ENF__COUNT not bumped
**What goes wrong:** `AC_ENF__COUNT` is 3 after current implementation (SELFPROTECT=1, MEMORY=2, COUNT=3). Adding new enforcers without bumping COUNT breaks any code iterating over the range.
**How to avoid:** After adding INJECT, EXECVE, PROC, set `AC_ENF__COUNT` to the next value after the last defined ID.
**Warning signs:** Failing test that checks an enforcer ID against COUNT.

---

## Code Examples

### Enum Extension (REQ-04)

```c
// Source: src/shared/ac.h [VERIFIED] — current state shown, extension pattern shown
enum ac_enforcer {
  AC_ENF_SELFPROTECT = 1,
  AC_ENF_MEMORY      = 2,
  AC_ENF_INJECT      = 3,  // NEW: mmap_file / file_mprotect
  AC_ENF_EXECVE      = 4,  // NEW: bprm_check_security
  /* AC_ENF_PROC = 5, */   // NEW: file_open (conditional on REQ-03 audit)
  AC_ENF__COUNT      = 5,  // update to 6 if AC_ENF_PROC is added
};
```

### CLI enforcer_name() Extension (REQ-08)

```c
// Source: src/cli/main.c [VERIFIED] — add cases to existing switch
static const char *enforcer_name(unsigned int id) {
  switch (id) {
  case AC_ENF_SELFPROTECT: return "selfprotect";
  case AC_ENF_MEMORY:      return "memory";
  case AC_ENF_INJECT:      return "inject";    // NEW
  case AC_ENF_EXECVE:      return "execve";    // NEW
  /* case AC_ENF_PROC: return "proc"; */        // NEW (conditional)
  default:                 return "?";
  }
}
```

### Test Structure for inject enforcer (REQ-05 pattern)

```cpp
// Source: tests/memory.cpp [VERIFIED] — run_scenario pattern
TEST_CASE("inject enforcer blocks anonymous PROT_EXEC mmap", "[inject][mmap]") {
  run_scenario({
    .target = targets::flag_secret(),
    .attack = [](const target_info &info) -> int {
      // Attack: mmap anonymous PROT_EXEC inside the protected process
      // (or from outside — see Open Question A1 for domain choice)
      void *p = mmap(NULL, 4096, PROT_READ|PROT_EXEC,
                     MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
      if (p == MAP_FAILED) return 1;
      munmap(p, 4096);
      return 0;
    },
    .expect_enforcer = AC_ENF_INJECT,
    .verify_success = [](target &, const attack_result &) {
      // mmap returning non-MAP_FAILED is the capability under test
    },
  });
}
```

---

## Runtime State Inventory

Step 2.5 trigger check: Phase 1 is additive (new BPF hooks, new test files, enum extension). It is not a rename, refactor, or migration. No stored data, live service config, OS-registered state, secrets/env vars, or build artifacts are affected by this phase.

**Not applicable — greenfield addition phase.**

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| clang | BPF compilation | unknown (macOS dev machine) | — | Build target is Linux only; build must run on Linux CI |
| bpftool | Skeleton generation | unknown | — | Linux CI |
| libbpf | Loader | unknown | — | Linux CI |
| BPF LSM in kernel | Runtime enforcement | unknown | — | Tests skip cleanly if EPERM on ac_open |
| Catch2 3.11.0 | Test suite | via Conan | 3.11.0 | None — required |
| Linux kernel 5.10+ | CO-RE + BPF LSM | unknown | — | Minimum specified in CLAUDE.md |

Note: The working directory is macOS (darwin 25.3.0). Development workflow appears to target a Linux test host. The test suite handles this via `SKIP` on EPERM from `ac_open`. Phase 1 work (writing BPF headers, test files, enum changes) is platform-agnostic for editing; runtime validation requires Linux with BPF LSM active.

**Missing dependencies with no fallback on macOS:** All BPF-related tools (clang `-target bpf`, bpftool, libbpf). Plans must note that final validation requires a Linux host with `lsm=...,bpf` in the kernel command line.

[VERIFIED: docs/testing.md — "Without root, the protected SECTION skips cleanly via Catch2 SKIP"]

---

## Open Questions

### A1: inject enforcer victim domain — who is the caller?
**What we know:** `lsm/mmap_file` fires in the context of the process calling `mmap`. A process can only mmap into its own address space. An external attacker cannot `mmap` into the game process's address space (that would require ptrace+poketext, which `ptrace_access_check` already blocks).
**What's unclear:** REQ-01 says "blocks external processes from creating PROT_EXEC mappings targeting the protected subtree." If the only process that can mmap into the game's address space is the game itself, then the inject enforcer must fire when the game process (or a descendant) creates an unauthorized PROT_EXEC mapping — i.e., the caller IS in the protected subtree. Alternatively, the intent may be to block the attacker from mapping executable code in their own address space and then using ptrace to copy it in (ptrace blocks this). Three interpretations:
- (a) Fire when the protected process maps anonymous PROT_EXEC (no file, anonymous injection). This is the only direct route not covered by ptrace_access_check.
- (b) Fire when the protected process maps any PROT_EXEC file that is not in an approved path (hard to implement without logging).
- (c) Fire when any process maps a shared object file that will subsequently be dlopened into the game — not detectable at mmap_file alone.
**Recommendation:** Interpret as (a) — emit deny when `cur_pid()` is in protected subtree AND `prot & PROT_EXEC` AND `file == NULL` (anonymous mapping). This is clear, privacy-preserving, and testable. Verify with user before implementing.

### A2: execve enforcer first-exec problem
**What we know:** `ac_spawn_and_protect` attaches BPF *before* releasing the child via the barrier pipe. The child's first action after the barrier is to call `child_main`, which (in the `ac` CLI) calls `execvp`. So the child execs the game binary while the enforcer is already live. If the execve enforcer fires on all execs from the subtree, it blocks game startup.
**What's unclear:** Which approach is consistent with GOALS.md's "no central toggle" constraint? Options:
- (a) Only fire on exec from *descendants* of `ac_protected_root_pid`, not the root itself. Root's exec is the game startup; descendants should not exec without permission.
- (b) Use a one-shot rodata flag allowing the first exec from root (contradicts "no toggle").
- (c) Restructure `ac_spawn_and_protect` to attach after the child has exec'd — introduces a window before enforcement.
- (d) Only fire on exec of *files* that are not linked on the filesystem (memfd-based fileless execution via bprm_creds_from_file check).
**Recommendation:** Option (a) is the most consistent with GOALS.md — the root's own exec is its startup, and descendants should not re-exec. Confirm with user.

### A3: `/proc/<pid>/` coverage audit
**What we know:** `ptrace_access_check` is called via `mm_access()` which is invoked from `proc_mem_open` (for `/proc/<pid>/mem`). [CITED: blog.cloudflare.com/diving-into-proc-pid-mem] This confirms that `mem` and `environ` are covered. Other `/proc/<pid>/` files may or may not call `mm_access`.
**What's unclear:** Whether `/proc/<pid>/maps`, `/proc/<pid>/smaps`, `/proc/<pid>/auxv`, `/proc/<pid>/status`, `/proc/<pid>/cmdline`, etc. each call `mm_access` or some other (or no) LSM hook path. This must be determined by reading `fs/proc/base.c` in the kernel source or empirically via testing (open each file without enforcer → verify accessible; with enforcer → verify blocked or not).
**Recommendation:** Phase 1 implementation task must include this audit. REQ-03 explicitly requires it. The `file_open` enforcer should only be added if gaps are found. Do not assume coverage without verification.

### A6: test harness incompatibility for inject and execve scenarios
**What we know:** The existing `run_scenario` pattern (see `tests/support/ac.cpp`) runs the "attack" in an external attacker process forked by the test harness. This works perfectly for `memory` tests where an external process calls `process_vm_readv` targeting the protected PID. For `inject` (anonymous PROT_EXEC mmap) and `execve` (exec from within subtree), the attack must originate from *inside* the protected process — the caller must be a member of the protected subtree for the enforcer to fire. The current harness has no mechanism to drive an action from inside the protected target.
**What's unclear:** Which of the following approaches is acceptable?
- (a) `self_attack` field in `scenario_spec` — a callable sent to the target process via the existing stdin command protocol, executed inside the target child, with result read back before session drain. Requires extending `tests/support/target.hpp` and the target protocol.
- (b) New target factories (`targets::mmap_exec_self()`, `targets::exec_child()`) — the target's `target_fn` itself performs the malicious action (mmap PROT_EXEC or exec a child binary) immediately after printing READY. The test's "attack succeeds" section spawns this target without a session; "protected" section spawns it with a session. The existing `run_scenario` wrapper is not used.
- (c) Reinterpret the requirements so the attacker is always external — e.g., for inject, test that an *external* attacker cannot cause the game to map PROT_EXEC memory via some IPC mechanism. This may not satisfy REQ-01 and REQ-02 as written.
**Recommendation:** Option (b) (new target factories) is the smallest change to the test infrastructure. The `target_fn` signature already supports arbitrary code in the child; factories like `flag_secret()` demonstrate the pattern. The planner should design inject and execve test tasks around this factory approach rather than `run_scenario`. Confirm with user before writing test tasks for REQ-05 and REQ-06.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `source/` tracepoints + bpf_override_return | `src/` BPF LSM hooks + `return -EPERM` | Before this session | LSM deny is cleaner, no CONFIG_BPF_KPROBE_OVERRIDE dependency |
| Separate enforcer/server/client binaries | Single `ac` CLI + session API library | Before this session | Simpler deployment; no mTLS needed |
| BPF map for target PID (`target_pid_map`) | rodata (`ac_protected_root_pid`, `ac_self_pid`) | Before this session | Immutable post-load; hostile root cannot redirect |
| Per-enforcer on/off toggle | No toggle; domain checks in rodata | GOALS.md design decision | Eliminates single-point-of-bypass |

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | inject enforcer should fire when the protected process itself maps anonymous PROT_EXEC (interpretation (a) of REQ-01) | Open Questions | Wrong interpretation leads to an enforcer that never fires (no external mmap into another process) or fires too broadly |
| A2 | execve enforcer should fire on descendants of `ac_protected_root_pid` but not on the root's own first exec (option (a) of A2) | Open Questions | Blocks game startup if wrong; or fails to detect exec of malicious binaries by root process |
| A3 | `ptrace_access_check` covers `/proc/<pid>/mem` and `/proc/<pid>/environ` but NOT `/proc/<pid>/maps`, `/proc/<pid>/status`, etc. | Open Questions | If wrong (broader coverage), REQ-03 may require no `file_open` enforcer; if coverage is narrower, more paths need protecting |
| A4 | `bpf_d_path` / `bpf_path_d_path` is callable from `lsm.s/file_open` | Standard Stack, Pattern 4 | Verifier rejection at load time; fallback: parse dentry chain with BPF_CORE_READ without bpf_d_path |
| A5 | `bpf_get_current_task_btf()` (kernel 5.11+) returns a typed `struct task_struct *` directly — no cast required. Available on kernel 5.11+; minimum for this project is 5.10. [MEDIUM — one minor version gap] | Pattern 2, Pattern 3 | If running on exactly 5.10, fall back to `cur_pid()` only (pass `me` as both pid and target_pid in the event) |

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Catch2 3.11.0 (via Conan) |
| Config file | none — discovered via `catch_discover_tests` in `tests/CMakeLists.txt` |
| Quick run command | `sudo ctest --preset conan-debug --output-on-failure -R inject` |
| Full suite command | `sudo ctest --preset conan-debug --output-on-failure` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| REQ-01 | inject enforcer blocks PROT_EXEC mmap | integration | `sudo ctest --preset conan-debug -R inject` | ❌ Wave 0 |
| REQ-02 | execve enforcer blocks unauthorized exec | integration | `sudo ctest --preset conan-debug -R execve` | ❌ Wave 0 |
| REQ-03 | proc coverage audit (empirical) | integration | `sudo ctest --preset conan-debug -R proc` | ❌ Wave 0 (conditional) |
| REQ-04 | ac_enforcer enum correct | compile-time | cmake build succeeds | ❌ (enum update) |
| REQ-05 | inject test cases follow run_scenario | integration | `sudo ctest --preset conan-debug -R inject` | ❌ Wave 0 |
| REQ-06 | execve test cases follow run_scenario | integration | `sudo ctest --preset conan-debug -R execve` | ❌ Wave 0 |
| REQ-07 | proc test cases (if applicable) | integration | `sudo ctest --preset conan-debug -R proc` | ❌ Wave 0 (conditional) |
| REQ-08 | enforcer_name() updated in CLI | manual | `ac ./some-binary` shows correct enforcer name | ❌ (cli update) |
| REQ-09 | docs/testing.md updated | manual review | — | N/A |

### Sampling Rate
- **Per task commit:** `cmake --build --preset conan-debug` (compile check, no BPF load)
- **Per wave merge:** `sudo ctest --preset conan-debug --output-on-failure` on Linux test host
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `tests/inject.cpp` — covers REQ-01, REQ-05
- [ ] `tests/execve.cpp` — covers REQ-02, REQ-06 (depends on resolving A2)
- [ ] `tests/proc.cpp` — covers REQ-03, REQ-07 (conditional on audit)
- [ ] `src/bpf/inject.bpf.h` — BPF enforcer for REQ-01
- [ ] `src/bpf/execve.bpf.h` — BPF enforcer for REQ-02
- [ ] `src/bpf/proc.bpf.h` — BPF enforcer for REQ-03 (conditional)

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | yes | BPF LSM deny at kernel boundary |
| V5 Input Validation | no | no user input in BPF programs |
| V6 Cryptography | no | — |

### Known Threat Patterns for this Stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Bypassing LSM via unhooked path to /proc | Tampering | Audit all /proc/<pid>/* open paths in fs/proc/base.c (REQ-03) |
| TOCTOU: pid reuse after subtree root death | Elevation of Privilege | Already mitigated — ac_tear_down_after_root_death detaches on pidfd POLLIN |
| BPF program detachment by hostile root (SIGKILL loader) | Denial of service | Documented residual weakness in SCOPE.md; not addressable in Phase 1 |
| exec of attacker-controlled binary from within subtree | Tampering | Addressed by REQ-02 execve enforcer (pending design decision A2) |
| Anonymous PROT_EXEC mmap for shellcode injection | Tampering | Addressed by REQ-01 inject enforcer |

---

## Sources

### Primary (HIGH confidence)
- `src/bpf/mem.bpf.h`, `src/bpf/selfprotect.bpf.h`, `src/bpf/common.bpf.h` — verified from codebase; existing enforcer shape, rodata pattern, emit_deny, is_in_protected_subtree
- `src/shared/ac.h` — verified; current enum, session API
- `src/loader/ac.c` — verified; spawn_and_protect sequence, skeleton load, ring buffer
- `tests/memory.cpp`, `tests/support/ac.hpp`, `tests/support/ac.cpp` — verified; run_scenario pattern, session harness
- `tests/CMakeLists.txt`, `conanfile.py` — verified; Catch2 3.11.0, ctest configuration
- `src/bpf/CMakeLists.txt` — verified; BPF build pattern (BpfCompile module)
- `include/linux/lsm_hook_defs.h` at torvalds/linux — verified via WebFetch; `mmap_file`, `file_mprotect`, `bprm_check_security`, `bprm_creds_for_exec`, `file_open` hook signatures
- `STATE.md`, `GOALS.md`, `SCOPE.md`, `REQUIREMENTS.md`, `ROADMAP.md` — verified from codebase

### Secondary (MEDIUM confidence)
- [kernel docs: security_bprm_check](https://www.kernel.org/doc/html/latest/core-api/kernel-api.html) — bprm_check_security hook description and parameters
- [kernel docs: prog_lsm.html](https://docs.kernel.org/bpf/prog_lsm.html) — BPF_PROG macro, LSM chaining, file_mprotect example
- [Cloudflare blog: /proc/pid/mem](https://blog.cloudflare.com/diving-into-proc-pid-mem/) — confirms ptrace_access_check path via mm_access for /proc/pid/mem
- [Dawid Macek: eBPF LSM exec prevention (2025)](https://www.dawidmacek.com/posts/2025/ebpf-lsm-synchronous-execution-prevention/) — bprm_check_security SEC/BPF_PROG pattern

### Tertiary (LOW confidence)
- Sleepable LSM hooks set (LKML patch thread) — file_open confirmed in sleepable set, enabling bpf_d_path; specific kernel version not nailed down [ASSUMED]
- `bpf_get_current_task_btf()` availability on kernel 5.10 (project minimum) — available since 5.11; one-version gap requires confirmation [MEDIUM]

---

## Metadata

**Confidence breakdown:**
- Hook names and signatures: HIGH — verified from lsm_hook_defs.h
- Existing enforcer pattern: HIGH — verified from codebase
- inject victim domain: LOW — ambiguous, flagged A1
- execve first-exec problem: MEDIUM — problem clearly identified; resolution options listed, not confirmed
- /proc coverage audit: LOW — empirical audit required; cannot be determined from docs alone
- bpf_d_path from file_open: MEDIUM — sleepable set membership confirmed; exact verifier behavior [ASSUMED]

**Research date:** 2026-05-09
**Valid until:** 2026-06-09 (kernel APIs are stable; hook availability unlikely to change)
