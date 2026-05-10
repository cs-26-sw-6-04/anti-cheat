# BPF LSM Monitors

This document describes every BPF LSM enforcer in `src/bpf/`. Each enforcer is a
separate header included by `src/bpf/enforcers.bpf.c`, which compiles them into a
single BPF object loaded by the `ac` runtime at session open time.

## Architecture

```
src/bpf/
├── common.bpf.h      — shared helpers, ring buffer, rodata
├── enforcers.bpf.c   — single compilation unit that #includes all enforcer headers
├── selfprotect.bpf.h — lsm/ptrace_access_check  → AC_ENF_SELFPROTECT
├── mem.bpf.h         — lsm/ptrace_access_check  → AC_ENF_MEMORY
├── inject.bpf.h      — lsm/mmap_file            → AC_ENF_INJECT
├── execve.bpf.h      — lsm/bprm_check_security  → AC_ENF_EXECVE
└── proc.bpf.h        — lsm.s/file_open          → AC_ENF_PROC
```

### Shared infrastructure (`common.bpf.h`)

**Rodata constants** — burned in by the loader before `skel__load()`; immutable after attach:

| Constant | Type | Purpose |
|---|---|---|
| `ac_self_pid` | `volatile const __u32` | PID of the loader/enforcer process |
| `ac_protected_root_pid` | `volatile const __u32` | PID of the game process (protected subtree root) |

There is no per-enforcer enable/disable bit. A central toggle would be a single point of bypass (bitflip, kernel write-what-where, or debug binary). Enforcers decide whether to fire by checking victim domain only.

**Helpers:**

```c
__u32 cur_pid()
// Returns bpf_get_current_pid_tgid() >> 32 — the caller's TGID (user-space PID).
```

```c
bool is_in_protected_subtree(struct task_struct *t)
// Walks t->real_parent up to AC_ANCESTOR_WALK_DEPTH (64) steps.
// Returns true iff any ancestor's tgid == ac_protected_root_pid.
// Stops early at init (tgid <= 1). The walk uses real_parent (kernel bookkeeping),
// which cannot be redirected from userspace without a kernel module.
```

```c
void emit_deny(__u32 enforcer, __u32 attacker, __u32 victim)
// Reserves a slot in the BPF ring buffer and writes an ac_event{DENY} record.
// Fields: kind=AC_EVENT_DENY, enforcer, pid=attacker, target_pid=victim, denied_errno=-EPERM.
```

**Events** flow through a 256 KB `BPF_MAP_TYPE_RINGBUF` named `events`. The `ac_poll` /
`ac_next_event` API in `src/shared/ac.h` drains this buffer from userspace.

---

## Enforcer 1 — selfprotect (`selfprotect.bpf.h`)

**Hook:** `lsm/ptrace_access_check`  
**Enforcer ID:** `AC_ENF_SELFPROTECT = 1`  
**Kernel minimum:** 5.10

### What it protects

The loader/enforcer process itself (`ac_self_pid`). Any external process attempting to
ptrace-attach to the loader would allow an attacker to inspect or modify the enforcer,
read its BPF maps, or detach the BPF programs entirely.

### Filter logic

```
caller pid == ac_self_pid  →  return 0   (self-introspection, allow)
victim tgid != ac_self_pid →  return 0   (not targeting the loader, skip)
otherwise                  →  deny, emit AC_ENF_SELFPROTECT
```

```c
SEC("lsm/ptrace_access_check")
int BPF_PROG(selfprotect, struct task_struct *child, unsigned int mode, int ret) {
  if (ret) return ret;                     // pass prior LSM deny through
  __u32 victim = BPF_CORE_READ(child, tgid);
  if (victim != ac_self_pid) return 0;    // not targeting the loader
  __u32 me = cur_pid();
  if (me == ac_self_pid) return 0;        // loader reading its own /proc
  emit_deny(AC_ENF_SELFPROTECT, me, victim);
  return -EPERM;
}
```

The `ptrace_access_check` hook is called by `security_ptrace_access_check()` which the
kernel invokes for `ptrace(PTRACE_ATTACH)`, `process_vm_readv`, `process_vm_writev`, and
opens of `/proc/<pid>/mem`. All of these are blocked for the loader's PID.

---

## Enforcer 2 — memory (`mem.bpf.h`)

**Hook:** `lsm/ptrace_access_check`  
**Enforcer ID:** `AC_ENF_MEMORY = 2`  
**Kernel minimum:** 5.10

### What it protects

The game process and its entire descendant subtree. Blocks any **external** process from
performing ptrace-class operations on any member of the protected tree: ptrace attach,
`process_vm_readv`, `process_vm_writev`, and `/proc/<pid>/mem` open.

### Filter logic

```
victim is not in protected subtree  →  return 0   (unrelated process, skip)
caller == victim                    →  return 0   (self-introspection, allow)
otherwise                           →  deny, emit AC_ENF_MEMORY
```

```c
SEC("lsm/ptrace_access_check")
int BPF_PROG(mem_enforce, struct task_struct *child, unsigned int mode, int ret) {
  if (ret) return ret;
  __u32 me = cur_pid();
  __u32 victim = BPF_CORE_READ(child, tgid);
  if (me == victim) return 0;                      // self-access
  if (!is_in_protected_subtree(child)) return 0;   // not our subtree
  emit_deny(AC_ENF_MEMORY, me, victim);
  return -EPERM;
}
```

**Note on attribution:** `ptrace_access_check` is the single LSM hook called for ptrace,
`process_vm_readv`, and `process_vm_writev`. A split into separate `AC_ENF_PTRACE` and
`AC_ENF_PROCVM` IDs is not possible at this hook; all three attacks are attributed to
`AC_ENF_MEMORY`. See `docs/testing.md` for details.

**Coverage of `/proc/<pid>/` paths:** `ptrace_access_check` is called when opening
`/proc/<pid>/mem`, `maps`, `smaps`, and `auxv` (kernel ≥ 4.x). Paths `status`,
`cmdline`, and `environ` are not gated by `ptrace_access_check` and are covered by
`AC_ENF_PROC` (see below). See `docs/design-decisions.md` §A3.

---

## Enforcer 3 — inject (`inject.bpf.h`)

**Hook:** `lsm/mmap_file`  
**Enforcer ID:** `AC_ENF_INJECT = 3`  
**Kernel minimum:** 5.11 (`bpf_get_current_task_btf()`)

### What it protects

Prevents shellcode injection via anonymous `PROT_EXEC` `mmap()` called from **within**
the protected subtree. Because `mmap` can only map into the calling process's own address
space, there is no "external attacker" for this vector — the attacker is the compromised
game process (or a descendant) allocating a writable+executable buffer for shellcode.

File-backed `PROT_EXEC` mappings (legitimate shared library loads by `ld.so`) are
explicitly allowed (`file != NULL` guard).

**Design decision A1:** This enforcer is only safe for game targets that do not use JIT
runtimes (V8, Mono/Unity, JVM, LuaJIT, Wine), which also allocate anonymous `PROT_EXEC`
pages. If the game uses a JIT runtime, use A1 option-b (skip this enforcer) instead.
See `docs/design-decisions.md` §A1.

### Filter logic

```
prot does not include PROT_EXEC  →  return 0   (not executable, skip)
file != NULL                     →  return 0   (file-backed = legitimate library load)
caller not in protected subtree  →  return 0   (unrelated process, skip)
otherwise                        →  deny, emit AC_ENF_INJECT (attacker == victim == me)
```

```c
SEC("lsm/mmap_file")
int BPF_PROG(inject_mmap_enforce, struct file *file,
             unsigned long reqprot, unsigned long prot,
             unsigned long flags, int ret) {
  if (ret) return ret;
  if (!(prot & PROT_EXEC)) return 0;       // not executable
  if (file != NULL) return 0;              // file-backed = ld.so load, allow
  __u32 me = cur_pid();
  struct task_struct *t = bpf_get_current_task_btf();
  if (!is_in_protected_subtree(t)) return 0;
  emit_deny(AC_ENF_INJECT, me, me);        // caller is both attacker and victim
  return -EPERM;
}
```

`bpf_get_current_task_btf()` is used because `lsm/mmap_file` does not supply a
`task_struct` argument directly (unlike `ptrace_access_check`).

---

## Enforcer 4 — execve (`execve.bpf.h`)

**Hook:** `lsm/bprm_check_security`  
**Enforcer ID:** `AC_ENF_EXECVE = 4`  
**Kernel minimum:** 5.11 (`bpf_get_current_task_btf()`)

### What it protects

Prevents a compromised child inside the protected subtree from replacing itself via
`execve()` with an attacker-controlled binary (process replacement / privilege escalation
via exec).

### Root exemption

`ac_spawn_and_protect` releases the barrier after attaching BPF; the protected root's
**first** action is to `exec` the game binary. The enforcer must not block this startup
exec. Only **descendants** of the root (children, grandchildren, …) are blocked from
calling `exec`.

**Design decision A2:** The filter `me != ac_protected_root_pid` implements this. The
root's one startup exec does not open a bypass: `ac_spawn_and_protect` controls which
binary is exec'd (the game binary) and does not give the child any choice. See
`docs/design-decisions.md` §A2.

### Filter logic

```
me == ac_protected_root_pid      →  return 0   (startup exec, exempt)
caller not in protected subtree  →  return 0   (unrelated process, skip)
otherwise                        →  deny, emit AC_ENF_EXECVE (attacker == victim == me)
```

```c
SEC("lsm/bprm_check_security")
int BPF_PROG(execve_enforce, struct linux_binprm *bprm, int ret) {
  if (ret) return ret;
  __u32 me = cur_pid();
  if (me == ac_protected_root_pid) return 0;   // root's startup exec, allow
  struct task_struct *t = bpf_get_current_task_btf();
  if (!is_in_protected_subtree(t)) return 0;
  emit_deny(AC_ENF_EXECVE, me, me);            // caller is both attacker and victim
  return -EPERM;
}
```

**Privacy:** `bprm->file` (the path of the binary being exec'd) is not logged in the
event. Only PIDs are recorded.

---

## Enforcer 5 — proc (`proc.bpf.h`)

**Hook:** `lsm.s/file_open` (sleepable)  
**Enforcer ID:** `AC_ENF_PROC = 5`  
**Kernel minimum:** 5.11 (sleepable LSM hooks require 5.11)

### What it protects

Blocks `open()` on three `/proc/<protected_pid>/` paths that are **not** gated by
`ptrace_access_check` and are therefore not covered by `AC_ENF_MEMORY`:

| Path | Why not covered by mem.bpf.h |
|---|---|
| `/proc/<pid>/status` | World-readable; no ptrace gate in the kernel |
| `/proc/<pid>/cmdline` | World-readable; no ptrace gate |
| `/proc/<pid>/environ` | Owner/root only; no ptrace gate |

These paths leak the game's command line, environment variables, and memory statistics,
which an attacker could use for reconnaissance.

**Why sleepable (`lsm.s/...`)?** Inspecting dentry names via `bpf_core_read_str`
requires sleeping BPF helpers unavailable in non-sleepable programs.

### Filter logic

```
ac_protected_root_pid == 0          →  return 0  (no session, skip)
grandparent dentry name != "proc"   →  return 0  (not under /proc/, skip)
parent dentry name != "<target pid>" →  return 0  (different pid, skip)
filename not in {status,cmdline,environ} → return 0  (not an uncovered path, skip)
otherwise                           →  deny, emit AC_ENF_PROC
```

```c
SEC("lsm.s/file_open")
int BPF_PROG(proc_enforce, struct file *file, int ret) {
  if (ret) return ret;
  if (!ac_protected_root_pid) return 0;

  // Walk: file → dentry → parent (pid dir) → grandparent ("proc")
  struct dentry *de  = BPF_CORE_READ(file, f_path.dentry);
  struct dentry *par = BPF_CORE_READ(de,   d_parent);
  struct dentry *gp  = BPF_CORE_READ(par,  d_parent);

  // Grandparent must be named "proc"
  char gp_name[8] = {};
  bpf_core_read_str(gp_name, sizeof(gp_name), BPF_CORE_READ(gp, d_name.name));
  if (gp_name[0]!='p'||gp_name[1]!='r'||gp_name[2]!='o'||gp_name[3]!='c'||gp_name[4]!='\0')
    return 0;

  // Parent name must match the protected root pid as a decimal string
  char expected[12] = {};
  pid_to_str(ac_protected_root_pid, expected, sizeof(expected));
  char par_name[12] = {};
  bpf_core_read_str(par_name, sizeof(par_name), BPF_CORE_READ(par, d_name.name));
  for (int i = 0; i < 11; i++) {
    if (expected[i] != par_name[i]) return 0;
    if (expected[i] == '\0') break;
  }

  // File must be one of the three uncovered paths
  if (!is_uncovered_proc_file(de)) return 0;

  __u32 me = cur_pid();
  emit_deny(AC_ENF_PROC, me, ac_protected_root_pid);
  return -EPERM;
}
```

`is_uncovered_proc_file()` uses character-by-character comparison (no `strcmp`) to stay
verifier-friendly. Each comparison checks the full string including the NUL terminator
at the expected index.

**Fail-open note:** If any `BPF_CORE_READ` or `bpf_core_read_str` call fails (e.g.,
transient memory pressure), the zero-initialised buffers cause all checks to fail and the
function returns 0 (allow). This is an accepted tradeoff; a future improvement would add
a dropped-event counter map.

---

## Coverage table

| Attack vector | Enforcer | Hook |
|---|---|---|
| `ptrace(PTRACE_ATTACH)` against game | `AC_ENF_MEMORY` | `lsm/ptrace_access_check` |
| `process_vm_readv` / `process_vm_writev` against game | `AC_ENF_MEMORY` | `lsm/ptrace_access_check` |
| `open(/proc/<pid>/mem)` | `AC_ENF_MEMORY` | `lsm/ptrace_access_check` |
| `open(/proc/<pid>/maps)`, `smaps`, `auxv` | `AC_ENF_MEMORY` | `lsm/ptrace_access_check` |
| `open(/proc/<pid>/status)`, `cmdline`, `environ` | `AC_ENF_PROC` | `lsm.s/file_open` |
| Anonymous `PROT_EXEC` mmap from within game | `AC_ENF_INJECT` | `lsm/mmap_file` |
| `execve` from game descendant | `AC_ENF_EXECVE` | `lsm/bprm_check_security` |
| Any ptrace against the enforcer/loader itself | `AC_ENF_SELFPROTECT` | `lsm/ptrace_access_check` |

All five enforcers are loaded as a single combined BPF object (`enforcers.bpf.c`). The
kernel runs them as a chain: each enforcer in the chain sees the prior `ret` value and
passes non-zero returns through unchanged (`if (ret) return ret`), so a deny from any
earlier hook in the chain is preserved.
