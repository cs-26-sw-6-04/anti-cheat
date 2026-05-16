/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LINUX_INJECT_LIB_H
#define LINUX_INJECT_LIB_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int linux_inject_so(pid_t target, const char *libpath, int *errnum);

#ifdef __cplusplus
}
#endif

#endif
