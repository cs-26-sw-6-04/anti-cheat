<!--
SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# CI Runner Setup

CI runs on a self-hosted GitHub Actions runner (label `ubuntu-25.10`). The
runner is a persistent VM, so system dependencies are provisioned once
out-of-band rather than reinstalled on every job. The workflow
(`.github/workflows/ci.yaml`) assumes everything below is already present.

If CI starts failing with "command not found" or missing headers, re-apply
the matching section on the runner VM.

## APT Packages

```sh
sudo apt-get update -q
sudo apt-get install -y \
  pipx \
  clang \
  llvm \
  gcc-15 \
  g++-15 \
  libstdc++-15-dev \
  libbpf-dev \
  cmake \
  pkg-config \
  libelf-dev \
  zlib1g-dev
```

## bpftool

The distro `bpftool` lags behind what we need for CO-RE skeleton generation,
so install the upstream static release:

```sh
BPFTOOL_VERSION=v7.6.0
curl -fsSL \
  "https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_VERSION}/bpftool-${BPFTOOL_VERSION}-amd64.tar.gz" \
  | sudo tar -xz -C /usr/local/bin
sudo chmod +x /usr/local/bin/bpftool
bpftool version
```

## mise

Install via apt: <https://mise.jdx.dev/installing-mise.html#apt>. Activate
for the runner user:

```sh
echo 'eval "$(mise activate bash)"' >> ~/.bashrc
```

## BPF LSM

Ubuntu 25.10 ships `bpf` disabled in the LSM stack. Enable it by appending
`bpf` to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`:

```sh
GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf"
```

The other entries are the distro default; read them from
`cat /sys/kernel/security/lsm` before editing so nothing is dropped. Then
`sudo update-grub && sudo reboot`, and verify `bpf` shows up in
`/sys/kernel/security/lsm`.

## sudo

`sudo ctest` must run passwordless for the test step.
