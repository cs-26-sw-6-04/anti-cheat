/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <cstring>
#include <string>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "ebpf_exfil_bpf.skel.h"
#include "targets.hpp"

using namespace ac;

namespace {
struct exfil_ctx {
  __u32 pid;
  __u64 addr;
  __s32 ret;
  char buf[64];
};
} // namespace

/* bpf_copy_from_user_task uses access_process_vm, which skips
 * security_ptrace_access_check. AC's LSM hooks never fire. See SCOPE.md. */
TEST_CASE("ebpf attack: bpf_copy_from_user_task exfils protected memory",
          "[ebpf-attack][exfil]") {
  auto t = targets::flag_secret()();
  auto sess = session::open_or_skip(t.info().root_pid);

  auto *skel = ebpf_exfil_bpf__open_and_load();
  REQUIRE(skel != nullptr);

  exfil_ctx ctx{};
  ctx.pid = t.info().pid;
  ctx.addr = t.info().addr;

  bpf_test_run_opts opts{};
  opts.sz = sizeof(opts);
  opts.ctx_in = &ctx;
  opts.ctx_size_in = sizeof(ctx);

  int err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.exfil), &opts);
  REQUIRE(err == 0);
  REQUIRE(ctx.ret == 0);
  REQUIRE(std::string(ctx.buf, strnlen(ctx.buf, sizeof(ctx.buf))) ==
          t.info().flag);

  sess.poll();
  REQUIRE_FALSE(sess.next_event().has_value());

  ebpf_exfil_bpf__destroy(skel);
}
