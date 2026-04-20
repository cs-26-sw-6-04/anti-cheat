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
};
