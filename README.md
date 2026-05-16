<!--
SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# anti-cheat

Anti-cheat using libbpf and BPF CO-RE.

## Enforcers

Two LSM programs, both hooked on `ptrace_access_check`:

- `AC_ENF_SELFPROTECT` — denies anything that would let an attacker reach the loader process (ptrace, `process_vm_*`, opens of the loader's procfs memory files).
- `AC_ENF_MEMORY` — same denial set, scoped to any task in the protected subtree (root + descendants, walked via `task->real_parent`).

The threat model is in `SCOPE.md`. The two enforcers cover the only attack vectors there that the kernel exposes a usable hook for. Everything else was considered and dropped — see the commit log for `proc`, `execve`, and `inject` for the empirical reasoning behind each removal.

## Examples

Install once: `sudo chown root:root build/<preset>/src/cli/ac && sudo chmod u+s !$`. Then run as your normal user — `ac` will drop privileges before exec'ing the target.

```sh
ac glxgears                       # native C/OpenGL
ac java -version                  # HotSpot JVM
ac luajit -e "for i=1,1e5 do end" # LuaJIT
ac node -e "console.log(42)"      # V8
ac wine cmd /c "echo hello"       # Wine non-GUI
ac wine /usr/lib/wine/x86_64-windows/winemine.exe   # Wine GUI
```

All run with zero deny events on the protected process itself.

## Known Limitation: GNOME window-to-app mapping

When the protected app's window appears, `gnome-shell` (and similar compositors) reads `/proc/<pid>/maps` to identify the binary for icon lookup and `.desktop` matching. That read goes through `ptrace_access_check` with `PTRACE_MODE_READ`, and `AC_ENF_MEMORY` denies it. The app keeps running, but the window may show a generic icon and the activities overview may misattribute it.

`/proc/<pid>/maps` exposes memory *layout* (mapping addresses, library list). It does **not** expose memory contents — `/proc/<pid>/mem` is the only path that does, and it shares the same LSM hook with the same mode bits. So today's `mem.bpf.h` denies both, and we lose the UX side to protect the exfil side.

### Possible fix without trusting any binary

Split the enforcement across two hooks instead of one:

1. Relax `mem.bpf.h` (`ptrace_access_check`) to deny only `PTRACE_MODE_ATTACH`. That still blocks `ptrace(PTRACE_ATTACH)`, `process_vm_readv`, and `process_vm_writev` — all the attach-mode operations. `PTRACE_MODE_READ` opens (maps, smaps, auxv, mem, environ) fall through.
2. Add a small enforcer on `lsm/file_open` that denies opens of `/proc/<protected_pid>/mem` specifically. Detection uses kernel structure inspection, no userspace identity:
   - `file->f_inode->i_sb->s_type->name == "proc"` (this is the superblock's filesystem-type name, not a dentry walk — robust across kernels, and avoids the trap our earlier proc enforcer hit, where procfs's root dentry is named `"/"` not `"proc"`).
   - `file->f_path.dentry->d_name.name == "mem"`.
   - `dentry->d_parent->d_name.name == decimal(ac_protected_root_pid)`.

After the split, `gnome-shell`'s `/proc/<pid>/maps` read goes through; an attacker's `/proc/<pid>/mem` open is still denied, and ptrace/`process_vm_*` are still denied at the original hook.

Tradeoff: `/proc/<pid>/{maps,smaps,auxv,environ}` become readable by any local user (process memory *layout* leaks, not contents). Layout alone doesn't enable read/write — those still need `/proc/<pid>/mem` or `process_vm_*`, both still blocked. For privacy of env vars, kernel DAC already restricts `/proc/<pid>/environ` to the owner.

Not whitelisting any binary, not trusting any caller identity — just being honest about which procfs path is actually the exfil channel.

## Known Limitation: detached crash-reporter helpers

Out-of-process crash reporters intentionally detach from their parent so they survive the parent's death and can capture post-mortem state. The pattern: spawn a helper, `setsid()` (or double-fork), let it be reparented to PID 1, then `ptrace`/`process_vm_readv` the parent on demand to produce a stack trace or core dump. Examples we've hit: Chromium's `crashpad_handler` (used by every Chromium/Electron app) and the Fabric mod `CrashAssistant`, which launches a sibling Java process that reads Minecraft's `/proc/<pid>/maps` for stack symbolication.

`AC_ENF_MEMORY` denies these because subtree membership is decided by walking `task->real_parent`, and the detached helper's chain terminates at PID 1 without reaching the protected root. The protected app keeps running; what you lose is the helper's ability to produce a useful post-mortem when the app does crash.

### Possible fix

Replace the ancestor walk with an explicit membership map, populated at fork time:

1. Attach a BPF program to the `sched_process_fork` tracepoint. When the parent's tgid is in the map (or equals `ac_protected_root_pid`), insert the child's tgid.
2. Attach to `sched_process_exit` to remove tgids on death.
3. `mem_enforce` checks the hash map instead of walking ancestry.

This catches the parent → child link at the moment of fork, before the child has any chance to `setsid` and break the topological relationship. Tradeoffs: stateful enforcement (map size scales with live descendant count, needs a sane cap), and a seed-time gap if `ac_open` is called against an already-running root with existing descendants — solvable by enumerating `/proc/<root>/task/*/children` at attach time.

Still no whitelist and no binary trust — the rule is "anything ever forked from the root counts as part of the root," which the kernel can observe directly.

## Notes

`vmlinux.h` is generated automatically from `/sys/kernel/btf/vmlinux`.
Pass `-DVMLINUX_H_DIR=<dir>` to use a pre-built one instead.

Unprivileged runs may skip live BPF tests.

## Dependencies

### apt (Debian/Ubuntu)

```sh
apt install clang llvm libbpf-dev linux-tools-common cmake pkgconf libelf-dev zlib1g-dev
```

Install mise with: <https://mise.jdx.dev/installing-mise.html#apt>

### dnf (Fedora/RHEL)

```sh
dnf install clang cmake libbpf-devel bpftool pkgconf elfutils-libelf-devel zlib-devel
```

Install mise with: <https://mise.jdx.dev/installing-mise.html#dnf>

### Project tools

```bash
# ~/.bashrc
eval "$(mise activate bash)"
```

```sh
mise install
```

## Debug

```sh
conan profile detect --force
conan install . -s build_type=Debug --build=missing
cmake --preset conan-debug
cmake --build --preset conan-debug
ctest --preset conan-debug
sudo ctest --preset conan-debug --output-on-failure
```

## Release

```sh
conan profile detect --force
conan install . -s build_type=Release --build=missing
cmake --preset conan-release
cmake --build --preset conan-release
ctest --preset conan-release
sudo ctest --preset conan-release --output-on-failure
./build/release-conan/loader/ac-loader
```

## One target

```sh
cmake --build --preset conan-release --target ac-loader
cmake --build --preset conan-release --target integration_tests
```
