<!--
SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# anti-cheat

Anti-cheat using libbpf and BPF CO-RE (Compile Once, Run Everywhere).

## Enforcers

All BPF LSM programs live in `src/bpf/` and are loaded as one combined object. See each header for motivation and filter logic.

- `selfprotect.bpf.h` — `lsm/ptrace_access_check` → `AC_ENF_SELFPROTECT`. Blocks ptrace/process_vm_*/`/proc/<pid>/mem` against the loader itself.
- `mem.bpf.h` — `lsm/ptrace_access_check` → `AC_ENF_MEMORY`. Blocks the same operations against any process in the protected subtree.

Intentionally **not** enforced:

- Anonymous `PROT_EXEC` mmap (shellcode injection from inside the subtree). Considered and rejected: the canonical W^X bypass (`mmap(RW)` + `mprotect(+X)`) sidesteps `mmap_file` entirely, so a serious attacker is unaffected; the only callers it does catch are legitimate ones that take the one-step shape — Wine's PE loader and HotSpot JVM's code cache. Confirmed empirically: `ac wine winemine.exe` died on a `create_view` assertion after the first `mmap(PROT_EXEC)` was denied; `ac java -version` printed `os::commit_memory ... Operation not permitted` and exited 1. With the enforcer removed, both run cleanly.
- `execve` from descendants. Doesn't defend a §3.1 property (the game-as-root re-execing is the integrity case, and the current shape would have to *allow* that to keep startup working). Breaks Wine, Steam/Proton, shell scripts, and every launcher chain on contact.
- `/proc/<pid>/{status,cmdline,environ}`. None of them leak memory content — `/proc/<pid>/mem` is the only path that does, and `AC_ENF_MEMORY` already gates it. Blocking these would break `ps`, `htop`, `gnome-system-monitor`, and every other tool that scans `/proc`.

## Examples

Install once: `sudo chown root:root build/<preset>/src/cli/ac && sudo chmod u+s !$`. After that, run as your normal user.

```sh
ac glxgears                       # native C/OpenGL
ac java -version                  # HotSpot JVM
ac luajit -e "for i=1,1e5 do end" # LuaJIT
ac node -e "console.log(42)"      # V8
ac wine cmd /c "echo hello"       # Wine non-GUI
ac wine /usr/lib/wine/x86_64-windows/winemine.exe   # Wine GUI
```

All of the above run with zero ac deny events on the protected process itself. External processes (gnome-shell, system monitors) may produce one-off `AC_ENF_MEMORY` denials when they probe `/proc/<pid>/maps` for window-to-app matching; those are correct enforcement and harmless — the protected program keeps running.

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
