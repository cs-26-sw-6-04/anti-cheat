# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

A research testbed for kernel-level runtime integrity verification of game processes on Linux using eBPF. The system implements the design described in the project report (P6.pdf), which grounds every design decision in a formal threat model and a set of security properties. All implementation choices must trace back to the report — this is an academic project and fidelity to the written design is required.

The system is a **preventive** anti-cheat: it blocks unauthorised interactions with the monitored game process at the syscall boundary **before** they take effect, rather than detecting them after the fact.

## Architecture

```
INTERNET
  └── Server          (game server analog — receives detections, sends BLOCK/INTERRUPT)

USERSPACE
  ├── Client          (simulates the game process — the monitored target)
  ├── Adversary       (simulates a cheat — triggers attack scenarios against the client)
  └── Enforcer        (loads eBPF monitors, reads events, enforces whitelist, talks to server)

KERNEL (trusted — Secure Boot assumed)
  └── Monitors        (eBPF programs attached to syscall tracepoints — write to ring buffers)
```

The enforcer spans both layers: it loads eBPF programs into the trusted kernel, reads events from ring buffers, applies the whitelist policy, and relays detections to the server over mTLS.

## Threat Model (report Chapter 3) — Implementation Contract

The implementation must enforce the **four security properties** from §3.1:

1. **Execution integrity** — the game executable and its loaded libraries must not be modified or replaced; no code injection or hooking via `LD_PRELOAD` or `ptrace`.
2. **Memory confidentiality** — no external process may read game process memory (unauthorised reads are violations even without writes).
3. **Monitor availability** — the eBPF monitoring programs must remain active and responsive for the full game session.
4. **Observation boundedness** — the monitoring system must be provably unable to observe activity outside the monitored game process (non-interference).

The **in-scope attack vectors** (§3.3, §2.8) that monitoring must cover:

| Attack | Syscalls to intercept |
|---|---|
| Memory read via ptrace | `ptrace` (any request targeting the monitored PID) |
| Memory write via ptrace | `ptrace` (any request targeting the monitored PID) |
| Memory read/write via `/proc/{pid}/mem` | `openat` on a path under `/proc/<target_pid>/` |
| Memory read/write via cross-process syscalls | `process_vm_readv`, `process_vm_writev` |
| Code injection via shared library loading | `mmap` with `PROT_EXEC` from an external process |
| Library injection via runtime ptrace | `ptrace` (covered above) |

Out-of-scope (precluded by Secure Boot assumption, do not monitor): kernel module loading, `/dev/mem`, hypervisor attacks.

## Whitelist Policy (report §6.3.3)

Not all inter-process interactions with the game are malicious. Legitimate components — graphics drivers, Proton/Wine compatibility layers, system libraries — may require controlled access. The whitelist defines which processes are permitted to interact with the monitored game process.

**Implementation requirements:**
- The enforcer maintains a whitelist of PIDs (and optionally executable paths) that are permitted to perform otherwise-blocked syscalls against the client.
- Any syscall interaction from a **non-whitelisted** process that would enable memory inspection, modification, or execution control must be **blocked before completion** via `bpf_override_return()` or equivalent mechanism.
- Whitelisted processes are allowed through without interference.
- The whitelist must be configurable (e.g. read from a file or CLI arguments) before the enforcer attaches the monitors.

## Current Implementation Status

The following is already implemented and working:

- `source/monitors/ptrace_monitor.bpf.c` — detects `ptrace` targeting the monitored PID; reports `ptrace_event` via ring buffer.
- `source/monitors/procvm_monitor.bpf.c` — detects `process_vm_writev` targeting the monitored PID; reports `vm_write_event` via ring buffer.
- `source/common/events.h` — shared event structs (`ptrace_event`, `vm_write_event`).
- `source/common/protocol.h` — wire protocol (`msg_header_t`, `MSG_HEARTBEAT`, `MSG_DETECTION`, `MSG_ACK`, `MSG_BLOCK`, `MSG_INTERRUPT`).
- `source/common/transport.{h,c}` — mTLS send/recv over TCP (OpenSSL).
- `source/enforcer/main.c` + `protocol.c` — loads skeleton, sets `target_pid_map`, polls ring buffer, sends heartbeats, handles `MSG_BLOCK`/`MSG_INTERRUPT`.
- `source/server/main.c` + `protocol.c` — listens for enforcer, prints detections, optionally sends `MSG_BLOCK` on detection.
- `source/client/main.c` — minimal game process stub; prints its PID.
- `source/adversary/main.c` — two attack scenarios: `ptrace_attach` and `proc_mem_write`.

**What is missing (must be implemented):**

- `process_vm_readv` monitor (currently only `process_vm_writev` is covered — reads violate memory confidentiality per §3.1).
- `openat` monitor filtering on `/proc/<target_pid>/` paths (covers `/proc/{pid}/mem` attack vector per §2.8.1).
- `mmap` monitor for external `PROT_EXEC` mappings (covers code injection vector per §2.8.2 and §6.3).
- Whitelist enforcement: monitors currently only report events; they do not block. Blocking must be added (see §6.1, §6.2).
- Whitelist management: enforcer needs a mechanism to configure which PIDs are allowed (e.g. Proton processes).
- Additional adversary scenarios matching the new monitors (`proc_mem_read`, `proc_mem_open`, `mmap_inject`).

## Build

**Dependencies (Debian/Ubuntu):**
```bash
apt install clang llvm libbpf-dev linux-tools-common cmake pkgconf libelf-dev zlib1g-dev libssl-dev
```

**Build:**
```bash
cmake --preset debug
cmake --build --preset debug
```

Or as a single step: `cmake --workflow --preset debug`

**Run:**
```bash
./build/debug/source/server/server &
./build/debug/source/client/client &          # note the PID printed
sudo ./build/debug/source/enforcer/enforcer <pid>
./build/debug/source/adversary/adversary <pid>
```

**Adding a new BPF monitor:** Place `<name>.bpf.c` in `source/monitors/`, add `add_bpf_object(<name> <name>.bpf.c ...)` and list it in `add_bpf_skeleton(...)` in `source/monitors/CMakeLists.txt`. The combined skeleton (`combined_bpf_lib`) is rebuilt automatically.

## Language and Build System

- **Language:** C (C11, no extensions)
- **Build system:** CMake ≥ 3.14 with presets (`CMakePresets.json`)
- **eBPF toolchain:** libbpf + clang (`-target bpf`); bpftool generates C skeleton headers (`bpf-skeleton.h`)
- In-source builds are forbidden by `CMakeLists.txt`
- clangd uses the compilation database at `build/debug/compile_commands.json`
- Each component (client, adversary, enforcer, server) is its own CMake target

## eBPF Conventions

- All BPF programs **must** declare `char LICENSE[] SEC("license") = "GPL"` — kernel BPF helpers are GPL-exported symbols and the verifier enforces this.
- Use `BPF_MAP_TYPE_RINGBUF` for event delivery (not `BPF_MAP_TYPE_PERF_EVENT_ARRAY`).
- Use `BPF_MAP_TYPE_ARRAY` with `max_entries = 1` for the `target_pid_map` — userspace writes the client PID into slot 0 before attaching.
- Avoid unbounded loops — all programs must pass the kernel verifier.
- Use `bpf_ktime_get_ns()` for event timestamps.
- Use `bpf_get_current_pid_tgid() >> 32` to get the caller PID.

## Non-Interference Constraint (report §3.1 — Observation Boundedness)

**Every eBPF monitor must filter on the target process as its first action** and return immediately for all unrelated activity. This is the structural enforcement of the observation boundedness property: the verifier's confinement guarantees that a correctly written program cannot observe anything outside the monitored process.

For monitors that filter on the **caller** (e.g. `mmap`, `openat` by the game process itself — not relevant for the attack vectors above), filter on `bpf_get_current_pid_tgid() >> 32`.

For monitors that filter on the **target** argument (i.e. detecting external attackers targeting the game — the primary attack surface), filter on the syscall argument that names the target PID:

```c
// Example: ptrace monitor filters on args[1] (the pid being ptraced)
SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid_arg = (__u32)ctx->args[1];   // target of ptrace call
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!tpid || *tpid == 0 || pid_arg != *tpid)
        return 0;
    // ... emit event ...
}
```

This pattern must be followed for all monitors. Never iterate over all processes or read from unrelated kernel structs.

## Blocking vs. Reporting

The report (§6.1) specifies a **preventive model**: interactions are blocked before they affect the game process.

To block a syscall from eBPF, use `bpf_override_return(ctx, -EPERM)` (requires `CONFIG_BPF_KPROBE_OVERRIDE`, available on most distros). This must be called **at syscall entry** (not exit). Only non-whitelisted processes should be blocked; whitelisted PIDs are allowed through.

The current monitors only report — they do not block. When adding blocking:
1. Keep reporting (emit to ring buffer) so the enforcer and server receive the event.
2. Add the `bpf_override_return` call immediately after the report submission for non-whitelisted callers.
3. The whitelist of allowed PIDs must be stored in a BPF map accessible from both the eBPF program and the enforcer userspace (use a `BPF_MAP_TYPE_HASH` keyed by PID).

## Communication: Enforcer ↔ Server

**Protocol:** TCP over mTLS (mutual TLS). TCP is required — a dropped connection must be unambiguous, not silent. Detection signals cannot be lost.

Message types are defined in `source/common/protocol.h`:

```c
MSG_HEARTBEAT  = 0x01   // enforcer -> server, every ~1 s
MSG_DETECTION  = 0x02   // enforcer -> server, cheat detected (payload = event struct)
MSG_ACK        = 0x03   // server -> enforcer, heartbeat acknowledged
MSG_BLOCK      = 0x04   // server -> enforcer, send SIGSTOP to target_pid
MSG_INTERRUPT  = 0x05   // server -> enforcer, send SIGINT to target_pid
```

Wire format: `msg_header_t` (17 bytes, packed, network byte order) followed by `payload_len` bytes. Use `msg_encode_header` / `msg_decode_header` from `common/protocol.h` — never write raw struct bytes over the wire.

## Security Invariants

These must not be violated in any implementation:

- **Replay protection:** `seq` is monotonically increasing per session; reject any message with `seq` ≤ last accepted `seq`.
- **Staleness check:** reject messages with `timestamp_ns` more than 5 seconds old.
- **mTLS:** both enforcer and server present X.509 certificates signed by the shared CA in `certs/`. Do not disable certificate verification.
- **Ring buffer overflow:** treat dropped events as a potential evasion — log and flag if `ring_buffer__consume` returns a negative value indicating loss.
- **No re-inspection from userspace:** trust the kernel-side event; do not ptrace the attacker process from userspace to "verify" the detection. This would introduce a TOCTOU race and violate the observation boundedness property.
- **Signal handling:** use `volatile sig_atomic_t` flags; no non-async-signal-safe calls inside signal handlers.
- **Single-threaded enforcer event loop:** do not add threads to the enforcer without a mutex. The current design uses `poll(2)` over the ring buffer epoll fd and the TLS socket fd.

## Testing

- The **adversary** has named scenarios triggerable with `--scenario <name>`: currently `ptrace_attach` and `proc_mem_write`. New monitors must have corresponding adversary scenarios.
- Each attack scenario must produce a `MSG_DETECTION` visible at the server.
- Use loopback TCP (`127.0.0.1:9999`) for enforcer/server communication in all tests.
- cmocka for unit tests: `apt install libcmocka-dev`

## Implementation Notes

- Linux 5.11+ minimum (required for BPF CO-RE via `vmlinux.h` from `/sys/kernel/btf/vmlinux`, and for `bpf_get_current_task_btf()` used by inject and execve enforcers).
- `CAP_BPF` or root is required at **runtime** only, not at compile time.
- If modifying `common/protocol.h`, update both enforcer and server — struct layout mismatches cause silent data corruption.
- If adding a new event type to `common/events.h`, add the corresponding `case` in both `enforcer/protocol.c` (`on_detection`) and `server/main.c` (`on_detection`).
- The combined BPF skeleton (`bpf-skeleton.h`) is auto-generated by the build; do not edit it manually.
- `target_pid_map` is shared across all BPF objects in the combined skeleton — writing to it once from the enforcer sets the target PID for all monitors simultaneously.
