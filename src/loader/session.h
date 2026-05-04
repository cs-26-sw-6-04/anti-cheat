/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

#include "ac.h"
#include "enforcers_bpf.skel.h"

#include <bpf/libbpf.h>

struct ac_session {
  struct enforcers_bpf *skel;
  struct ring_buffer *events;
  struct ac_event next;
  int has_next;
  /* pidfd of the protected root, or -1 when no subtree is registered. Lets
   * ac_poll detect root death via a single poll(2) call alongside the ring
   * buffer fd, and binds the watch to the original task_struct so PID reuse
   * after ac_open cannot fool us. */
  int root_pidfd;
  /* Sticky: set the first time poll observes pidfd POLLIN. Once set, the
   * session has torn down its BPF state and ac_poll returns -ESRCH for the
   * rest of its lifetime. */
  int root_dead;
};
