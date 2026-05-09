/*
 * SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * A3 /proc/<pid>/ coverage audit — one-shot diagnostic scaffold.
 *
 * Purpose: Empirically determine which /proc/<pid>/ paths are already blocked
 * by the AC_ENF_MEMORY enforcer (lsm/ptrace_access_check) and which require a
 * separate proc enforcer (lsm/file_open).
 *
 * Each path is tested TWICE:
 *   1. WITHOUT enforcer — proves the path is normally accessible (open succeeds)
 *   2. WITH enforcer    — checks whether AC_ENF_MEMORY blocks it (open fails)
 *
 * Results must be filled in after running on a Linux host with BPF LSM enabled:
 *   kernel 5.11+, CONFIG_BPF_LSM=y, lsm=...,bpf in kernel command line
 *   Run as root: sudo ctest --preset conan-debug -R "proc.*audit" --output-on-failure
 *
 * A3 AUDIT RESULT: /proc/<pid>/mem     -- [FILL IN AFTER RUNNING ON LINUX]
 * A3 AUDIT RESULT: /proc/<pid>/maps    -- [FILL IN AFTER RUNNING ON LINUX]
 * A3 AUDIT RESULT: /proc/<pid>/smaps   -- [FILL IN AFTER RUNNING ON LINUX]
 * A3 AUDIT RESULT: /proc/<pid>/auxv    -- [FILL IN AFTER RUNNING ON LINUX]
 * A3 AUDIT RESULT: /proc/<pid>/status  -- [FILL IN AFTER RUNNING ON LINUX]
 * A3 AUDIT RESULT: /proc/<pid>/cmdline -- [FILL IN AFTER RUNNING ON LINUX]
 * A3 AUDIT RESULT: /proc/<pid>/environ -- [FILL IN AFTER RUNNING ON LINUX]
 *
 * NOTE: This file is a one-shot diagnostic. Delete it in Wave 4 after recording
 * the A3 results in docs/design-decisions.md.
 */

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include "ac.hpp"
#include "targets.hpp"

using namespace ac;

/* Attempt to open a /proc/<pid>/<file> path and return the outcome string. */
static std::string try_open_proc(unsigned pid, const char *file) {
    char path[128];
    std::snprintf(path, sizeof(path), "/proc/%u/%s", pid, file);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        close(fd);
        return std::string("OPEN_OK (fd>=0): ") + path;
    }
    char errbuf[64];
    std::snprintf(errbuf, sizeof(errbuf), "OPEN_FAILED errno=%d (%s)", errno,
                  std::strerror(errno));
    return std::string(errbuf) + ": " + path;
}

TEST_CASE("A3 proc audit: /proc/<pid>/ path coverage by AC_ENF_MEMORY",
          "[proc][audit]") {

    /* Paths under audit. */
    static const char *const paths[] = {
        "mem",
        "maps",
        "smaps",
        "auxv",
        "status",
        "cmdline",
        "environ",
    };
    static const int n_paths = sizeof(paths) / sizeof(paths[0]);

    SECTION("without enforcer — paths must be accessible (open returns fd>=0)") {
        auto t = targets::flag_secret()();

        for (int i = 0; i < n_paths; ++i) {
            std::string result = try_open_proc(t.info().pid, paths[i]);
            INFO("path=" << paths[i] << "  result=" << result);
            /* No REQUIRE here — /proc/<pid>/mem always requires ptrace permission
             * even without our enforcer on some kernels; we just record what we
             * observe. The test prints INFO lines for manual inspection. */
            (void)result;
        }
    }

    SECTION("with enforcer — record which paths are blocked by AC_ENF_MEMORY") {
        auto t = targets::flag_secret()();
        auto sess = session::open_or_skip(t.info().root_pid);

        for (int i = 0; i < n_paths; ++i) {
            std::string result = try_open_proc(t.info().pid, paths[i]);
            INFO("path=" << paths[i] << "  result=" << result);
            /*
             * No REQUIRE: this is an audit, not a pass/fail assertion.
             * Inspect the INFO output to determine COVERED vs UNCOVERED:
             *   OPEN_FAILED errno=1 (EPERM)  -> COVERED by ptrace_access_check
             *   OPEN_OK (fd>=0)               -> UNCOVERED -- proc enforcer needed
             */
            (void)result;
        }
    }
}
