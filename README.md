<!--
SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# anti-cheat

Anti-cheat using libbpf and BPF CO-RE (Compile Once, Run Everywhere).

## Notes

`vmlinux.h` is generated automatically from `/sys/kernel/btf/vmlinux`.
Pass `-DVMLINUX_H_DIR=<dir>` to use a pre-built one instead.

Unprivileged runs may skip live BPF tests.

## Components

### client

The `client` binary simulates the monitored game process. It prints its PID on the first line
of stdout, then loops sleeping until SIGINT or SIGTERM.

```sh
./build/debug-conan/bin/client/client
# Prints the PID on the first line, e.g.:
# 12345
```

### enforcer-cli

The `enforcer-cli` binary requires root (or `CAP_BPF`) and a Linux kernel with BPF LSM in the
active LSM stack (`cat /sys/kernel/security/lsm` must list `bpf`). It opens a BPF LSM session,
protects the target PID with full policy (block ptrace and memory vectors), optionally whitelists
additional PIDs, then polls for deny events and prints each one to stdout until SIGINT or SIGTERM.

```sh
sudo ./build/debug-conan/bin/enforcer-cli/enforcer-cli <target-pid> [--whitelist <pid1>[,<pid2>,...]]
```

**Example session** (two terminals):

```sh
# Terminal 1 — start the client (game-process analog)
./build/debug-conan/bin/client/client
# 12345

# Terminal 2 — start the enforcer (requires root)
sudo ./build/debug-conan/bin/enforcer-cli/enforcer-cli 12345
# protecting pid 12345
# monitoring — press Ctrl-C to stop

# With a whitelisted PID (e.g. a trusted graphics driver process):
sudo ./build/debug-conan/bin/enforcer-cli/enforcer-cli 12345 --whitelist 9876,9877
# protecting pid 12345
# whitelisted pid 9876
# whitelisted pid 9877
# monitoring — press Ctrl-C to stop
```

When the enforcer is running and an unwhitelisted process attempts ptrace or cross-process memory
access against the client, the enforcer prints a DENY line:

```
DENY enforcer=PTRACE attacker=<pid> victim=12345 errno=-1
```

To observe blocking behaviour end-to-end, run the test suite as root on a Linux host with BPF LSM
active:

```sh
sudo ctest --preset conan-debug --output-on-failure
```

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
