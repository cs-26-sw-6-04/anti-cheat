/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

// Shared between the BPF program and the user-space loader.
// Must use only fixed-width types so the layout is identical on both sides.
struct event {
  __u32 pid;
  __u32 uid;
  char comm[16];
};
