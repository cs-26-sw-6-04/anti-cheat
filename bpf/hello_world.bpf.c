/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "hello_world.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(
    struct trace_event_raw_sys_enter *ctx) {
  struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (!e)
    return 0;

  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  bpf_get_current_comm(e->comm, sizeof(e->comm));

  bpf_ringbuf_submit(e, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
