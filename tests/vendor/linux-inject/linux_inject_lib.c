/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 * SPDX-FileCopyrightText: 2015 Tyler Colgan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Library adapter for gaffe23/linux-inject. Shadows three upstream
 * symbols so the 2015-era sources work on modern glibc and link as a
 * library rather than a binary: main() -> linux_inject_main(),
 * getlibcaddr() also matches "libc.so.6", and getFunctionAddress() falls
 * back from "__libc_dlopen_mode" (GLIBC_PRIVATE, gone since glibc 2.34)
 * to "dlopen".
 */

/* Headers upstream relies on but does not always include. */
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "linux_inject_lib.h"

#define getlibcaddr getlibcaddr_upstream_unused
#define getFunctionAddress getFunctionAddress_upstream_unused
#include "utils.c"
#undef getlibcaddr
#undef getFunctionAddress

#include "ptrace.c"

#define main linux_inject_main
#if defined(__x86_64__)
#  include "inject-x86_64.c"
#elif defined(__i386__)
#  include "inject-x86.c"
#else
#  error "linux-inject adapter: only x86_64 and i386 wired up"
#endif
#undef main

long getFunctionAddress(char *funcName) {
  void *self = dlopen("libc.so.6", RTLD_LAZY);
  if (!self)
    return 0;
  void *fa = dlsym(self, funcName);
  if (!fa && strcmp(funcName, "__libc_dlopen_mode") == 0)
    fa = dlsym(self, "dlopen");
  return (long)fa;
}

long getlibcaddr(pid_t pid) {
  char filename[40];
  char line[1024];
  long addr = 0;
  snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
  FILE *fp = fopen(filename, "r");
  if (!fp)
    return 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strstr(line, "libc-") || strstr(line, "libc.so")) {
      sscanf(line, "%lx", &addr);
      break;
    }
  }
  fclose(fp);
  return addr;
}

int linux_inject_so(pid_t target, const char *libpath, int *errnum) {
  char pid_str[32];
  snprintf(pid_str, sizeof(pid_str), "%d", (int)target);
  char prog[] = "linux-inject";
  char flag[] = "-p";
  char *argv[] = {prog, flag, pid_str, (char *)libpath, NULL};
  int rc = linux_inject_main(4, argv);
  if (errnum)
    *errnum = rc;
  return rc;
}
