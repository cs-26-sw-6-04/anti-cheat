/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifdef AC_DEBUG_BUILD

#include "ac.h"
#include "session.h"

#include <errno.h>

int ac_set_enforcer_enabled(struct ac_session *s, enum ac_enforcer id, int on) {
  if (!s)
    return -EINVAL;
  if (id <= 0 || id >= AC_ENF__COUNT)
    return -EINVAL;
  if (id == AC_ENF_SELFPROTECT)
    return -EPERM;

  /* skel->data is mmap'd; writes take effect immediately in the kernel. */
  s->skel->data->ac_enabled[id] = on ? 1 : 0;
  return 0;
}

#endif
