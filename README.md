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
- `inject.bpf.h` — `lsm/mmap_file` → `AC_ENF_INJECT`. Blocks anonymous `PROT_EXEC` mmap from inside the subtree (shellcode injection). File-backed `PROT_EXEC` (ld.so library loads) is allowed.
- `execve.bpf.h` — `lsm/bprm_check_security` → `AC_ENF_EXECVE`. Blocks `exec()` from a descendant of the protected root. The root's own startup exec is exempt.

`/proc/<pid>/{status,cmdline,environ}` are intentionally not enforced: none of them leak game memory content (the §3.1 memory-confidentiality property covers `/proc/<pid>/mem`, which `AC_ENF_MEMORY` already gates), and blocking them would break `ps`, `htop`, `gnome-system-monitor`, and every other tool that scans `/proc`.

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
