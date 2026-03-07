<!--
SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# anti-cheat

Anti-cheat using libbpf and BPF CO-RE (Compile Once, Run Everywhere).

## Dependencies

### apt (Debian/Ubuntu)

```sh
apt install clang llvm libbpf-dev linux-tools-common cmake pkgconf libelf-dev zlib1g-dev
```

### dnf (Fedora/RHEL)

```sh
dnf install clang cmake libbpf-devel bpftool pkgconf elfutils-libelf-devel zlib-devel
```

## Build

```sh
cmake -B build/debug -S .
cmake --build build/debug
```

Alternatively, use CMake workflows:

```bash
# Configure + build in one shot
cmake --workflow --preset debug
cmake --workflow --preset release

# Or separately
cmake --preset debug
cmake --build --preset debug
```

`vmlinux.h` is generated automatically from `/sys/kernel/btf/vmlinux`.
Pass `-DVMLINUX_H_DIR=<dir>` to use a pre-built one instead.

## Run

```sh
sudo ./build/debug/loader/ac-loader
```
