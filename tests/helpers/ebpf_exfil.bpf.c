/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EBPF_EXFIL_SIZE 64

struct exfil_ctx {
  __u32 pid;
  __u64 addr;
  __s32 ret;
  char buf[EBPF_EXFIL_SIZE];
};

extern struct task_struct *bpf_task_from_pid(__s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

SEC("syscall")
int exfil(struct exfil_ctx *ctx) {
  char tmp[EBPF_EXFIL_SIZE] = {};

  struct task_struct *task = bpf_task_from_pid(ctx->pid);
  if (!task) {
    ctx->ret = -3; /* -ESRCH */
    return 0;
  }

  ctx->ret = bpf_copy_from_user_task(tmp, EBPF_EXFIL_SIZE,
                                     (void *)(unsigned long)ctx->addr, task, 0);
  bpf_task_release(task);

  __builtin_memcpy(ctx->buf, tmp, EBPF_EXFIL_SIZE);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
