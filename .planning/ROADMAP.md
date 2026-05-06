# Roadmap: eBPF Anti-Cheat Testbed

**Created:** 2026-05-04
**Granularity:** Standard (5-8 phases)
**Coverage:** 13/13 v1 requirements mapped

## Phases

- [ ] **Phase 1: Whitelist Infrastructure + Stable Client** - Foundation: whitelist BPF map, enforcer CLI config, stable client loop
- [ ] **Phase 2: Block Existing Monitors** - Verify BLOCK-01/BLOCK-02 coverage via explicit requirement-tagged tests; add README Components section
- [ ] **Phase 3: Memory-Read Vector** - process_vm_readv monitor + standalone attacker; vertical slice proves block end-to-end
- [ ] **Phase 4: Procfs Vector** - openat /proc/<pid>/ monitor + standalone attacker; vertical slice proves block end-to-end
- [ ] **Phase 5: Code-Injection Vector + Live Demo** - mmap PROT_EXEC monitor + standalone attacker + full concurrent demo

## Phase Details

### Phase 1: Whitelist Infrastructure + Stable Client
**Goal**: The whitelist BPF hash map exists, is accessible from both BPF programs and enforcer userspace, the enforcer accepts PIDs via CLI args and populates the map before polling for events, and the client runs a stable signal-terminated loop that keeps its PID alive for the full session.
**Depends on**: Nothing (first phase)
**Requirements**: WLIST-01, WLIST-02, WLIST-03, DEMO-01
**Success Criteria** (what must be TRUE):
  1. A BPF_MAP_TYPE_HASH keyed by __u32 PID is declared in the combined skeleton and lookup from within a BPF program returns non-null for a PID that was inserted by enforcer userspace
  2. Running `sudo enforcer-cli <pid> --whitelist <pid1>,<pid2>` populates the whitelist map with the supplied PIDs before polling for events (note: ac_open() attaches monitors; map writes take effect immediately on the live skeleton because the BPF program reads the map fresh on each hook invocation)
  3. A PID present in the whitelist map passes through all monitor syscall checks without being blocked or generating a detection event
  4. The client process runs indefinitely in a sleep loop and exits only on SIGINT or SIGTERM — its PID remains stable for the full demo session
**Plans**: 4 plans

Plans:
- [x] 01-01-PLAN.md — whitelist_pids BPF map declaration + ac_whitelist_add/remove library API
- [x] 01-02-PLAN.md — bin/client stable signal-terminated loop binary
- [x] 01-03-PLAN.md — BPF enforcer whitelist short-circuit + Catch2 whitelist tests
- [x] 01-04-PLAN.md — bin/enforcer-cli CLI wrapper with --whitelist argument

### Phase 2: Block Existing Monitors
**Goal**: BLOCK-01 and BLOCK-02 are verified by explicit requirement-labelled Catch2 tests, and README.md documents the two existing runnable components (client, enforcer-cli) with accurate startup sequences and whitelist usage. Note: the BPF LSM blocking mechanism (return -EPERM from lsm/ptrace_access_check) and emit-before-block ordering were implemented in the e2224d4 refactor; Phase 2 is verification and documentation.
**Depends on**: Phase 1
**Requirements**: BLOCK-01, BLOCK-02
**Success Criteria** (what must be TRUE):
  1. tests/block.cpp exists with TEST_CASEs named "... — BLOCK-01" (×3) and "... — BLOCK-02" (×1), all using run_scenario
  2. On Linux with BPF LSM active: sudo ctest --preset conan-debug -R "BLOCK-01|BLOCK-02" passes all tests
  3. README.md has a ## Components section documenting client and enforcer-cli with accurate build/debug-conan/ paths
  4. README.md --whitelist usage is documented with an example two-terminal session
**Plans**: 2 plans

Plans:
- [x] 02-01-PLAN.md — tests/block.cpp with explicit BLOCK-01/BLOCK-02 requirement-labelled Catch2 tests
- [x] 02-02-PLAN.md — README.md ## Components section for client and enforcer-cli

### Phase 3: Memory-Read Vector
**Goal**: A new process_vm_readv eBPF monitor intercepts cross-process memory reads targeting the game PID, emits a ring buffer event, and blocks non-whitelisted callers — verified end-to-end by a standalone attacker binary that receives EPERM.
**Depends on**: Phase 2
**Requirements**: MONITOR-01, ATTACK-01
**Success Criteria** (what must be TRUE):
  1. The process_vm_readv monitor filters on the target PID as its first action (observation boundedness — unrelated calls return immediately without further work)
  2. Running the standalone process_vm_readv attacker binary against the game PID without a whitelist entry causes the attacker to receive EPERM
  3. A MSG_DETECTION event for process_vm_readv appears at the server, emitted before the block
  4. A whitelisted process calling process_vm_readv against the game PID is allowed through without a detection event or EPERM
**Plans**: TBD

### Phase 4: Procfs Vector
**Goal**: A new openat eBPF monitor intercepts open calls whose path falls under /proc/<target_pid>/ (e.g. /proc/<pid>/mem), emits a ring buffer event, and blocks non-whitelisted callers — verified end-to-end by a standalone attacker binary that receives EPERM.
**Depends on**: Phase 3
**Requirements**: MONITOR-02, ATTACK-02
**Success Criteria** (what must be TRUE):
  1. The openat monitor filters on path prefix /proc/<target_pid>/ as its first action; openat calls to unrelated paths return immediately
  2. Running the standalone openat attacker binary that opens /proc/<game_pid>/mem causes the attacker to receive EPERM
  3. A MSG_DETECTION event for the openat attempt appears at the server, emitted before the block
  4. A whitelisted process opening /proc/<game_pid>/mem is allowed through without a detection event or EPERM
**Plans**: TBD

### Phase 5: Code-Injection Vector + Live Demo
**Goal**: A new mmap eBPF monitor intercepts mmap calls with PROT_EXEC from processes other than the game PID, emits a ring buffer event, and blocks non-whitelisted callers — then the full system (client, enforcer, all attacker scenarios) runs concurrently and demonstrates every attack vector being blocked live.
**Depends on**: Phase 4
**Requirements**: MONITOR-03, ATTACK-03, DEMO-02
**Success Criteria** (what must be TRUE):
  1. The mmap monitor filters on caller PID (excluding the game PID itself) as its first action; mmap calls from the game process or unrelated processes not requesting PROT_EXEC return immediately
  2. Running the standalone mmap PROT_EXEC attacker binary causes the attacker to receive EPERM, and a deny event is logged by enforcer-cli
  3. A whitelisted process performing an mmap PROT_EXEC call is allowed through without a detection event or EPERM
  4. With all components running concurrently (client, enforcer), each of the attacker binaries can be run in any order and produces EPERM plus an enforcer-logged DENY line for each non-whitelisted invocation
**Plans**: TBD

## Progress Table

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Whitelist Infrastructure + Stable Client | 0/4 | Not started | - |
| 2. Block Existing Monitors | 2/2 | Complete | 2026-05-06 |
| 3. Memory-Read Vector | 0/? | Not started | - |
| 4. Procfs Vector | 0/? | Not started | - |
| 5. Code-Injection Vector + Live Demo | 0/? | Not started | - |

---
*Roadmap created: 2026-05-04*
*Last updated: 2026-05-05 after phase 2 planning*
