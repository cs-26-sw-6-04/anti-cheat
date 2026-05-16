<!--
SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Testing Strategy

BPF LSM programs must be loaded, attached, and triggered against the real
kernel path; `BPF_PROG_RUN` cannot stand in for that. The suite is therefore
an integration suite: every test case runs a real attacker process against a
real target process, with and without the enforcers active.

## Suite Layout

```
tests/
  support/          # session, target, run_attacker, run_scenario, matchers
  memory.cpp        # memory enforcer against the single protected target
  subtree.cpp      # subtree coverage: descendants in, outsiders out
  self_protect.cpp  # AC self-protection
```

One executable (`ac_tests`). Each `TEST_CASE` opens its own `ac::session`;
CTest runs cases serially to avoid live-session overlap.

## Enforcer Layout

- **`AC_ENF_SELFPROTECT`**: fires when the victim is the loader itself
  (`tgid == ac_self_pid`, which is burned into BPF rodata at skeleton load).
- **`AC_ENF_MEMORY`**: fires when the victim is in the protected subtree, as
  determined by a bounded `task->real_parent` walk looking for
  `ac_protected_root_pid` (also rodata).

There is no `AC_ENF_PTRACE`. `process_vm_{read,write}v` and
`ptrace(PTRACE_ATTACH)` all go through the same `lsm/ptrace_access_check`
hook with the same `PTRACE_MODE_ATTACH_REALCREDS` mode bits; the LSM layer
does not distinguish them, so splitting attribution between "memory access"
and "ptrace attach" at this hook would be dishonest. `AC_ENF_MEMORY` owns
the entire subtree-access domain and fires for all of the above.

## Writing a Test

Each scenario is a declarative spec passed to `run_scenario`, which executes
two SECTIONs automatically:

1. **attack succeeds (no enforcer)**: no session; the attack must succeed
   *and* `verify_success` must confirm the expected side-effect (bytes
   exfiltrated, target memory mutated, etc.). Exit code alone proves only
   that a syscall returned, not that the capability landed.
2. **protected**: a session is opened and the attack must fail with the
   correct attribution event. No runtime enforcer toggling: selfprotect and
   memory have disjoint victim domains (loader vs. subtree), so each attack
   matches at most one enforcer by construction.

Tokens (initial flag, mutation payload) are freshly randomized per-run by
`ac::random_token()` so attackers can't hardcode them.

```cpp
TEST_CASE("memory enforcer blocks process_vm_readv", "[mem][read]") {
  run_scenario({
      .target = targets::flag_secret(),
      .attack = [](const target_info &info) -> int {
        char buf[AC_FLAG_SIZE] = {0};
        iovec local{buf, sizeof(buf)};
        iovec remote{(void*)info.addr, std::min(info.len, sizeof(buf))};
        if (process_vm_readv(info.pid, &local, 1, &remote, 1, 0) < 0)
          return 1;
        buf[sizeof(buf) - 1] = '\0';
        fputs(buf, stdout);
        fflush(stdout);
        return 0;
      },
      .expect_enforcer = AC_ENF_MEMORY,
      .verify_success = [](target &t, const attack_result &r) {
        REQUIRE(r.stdout == t.info().flag);
      },
  });
}
```

The attack is a lambda inlined in the scenario, which reads top-to-bottom
with no indirection. Promote to a `tests/support/` helper only once it's
shared.

For mutation-style attacks (e.g. `process_vm_writev`), `verify_success` calls
`t.stop()` and asserts that `t.observed_flag()` (the `FLAG <value>` line
printed by the target on stdin EOF) matches the randomized payload the
attacker wrote.

Adding a new enforcer test: write a target factory in `support/targets.*` if
needed, an attacker factory in `support/attacks.*` if needed, then a one-file
`TEST_CASE`.

## Enforcer Attribution

Every deny event carries an `enforcer` field. The `FiredBy` Catch2 matcher
produces readable mismatch messages (e.g., `expected fired by
enforcer=MEMORY`, `got fired by enforcer=SELFPROTECT`).

There is no runtime on/off bit per enforcer. Both selfprotect and memory are
unconditional. Each enforcer's domain check (loader pid vs. subtree
ancestry) decides whether it fires for a given victim, and the two domains
are disjoint, so tests do not need a toggle to isolate which enforcer
fired. Debug and Release run the same code path.

## Running

```sh
mise x -- conan install . -s build_type=Debug --build=missing
cmake --preset conan-debug
cmake --build --preset conan-debug --parallel
ctest --preset conan-debug                              # baseline only
sudo ctest --preset conan-debug --output-on-failure     # with live BPF
```

Without root, the protected SECTION skips cleanly via Catch2 `SKIP`. The
"attack succeeds (no enforcer)" SECTION still runs and must pass, proving
the attack actually works on this kernel (and that the exfil/mutation landed)
before claiming the enforcer blocked it.
