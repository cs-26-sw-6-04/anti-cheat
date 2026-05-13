# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

add_executable(ac main.c)

target_link_libraries(ac
    PRIVATE
        ac_loader_runtime
)

# Per SCOPE.md, the dynamic loader, shared libraries, and process environment
# are hostile: an attacker with userspace control can LD_PRELOAD a stub, swap
# RPATH, or replace libbpf/libc on disk to neutralise the loader before its
# BPF hooks ever attach. A fully static binary has no PT_INTERP, no DT_NEEDED
# entries, and no dlopen surface, so none of those interposition paths apply.
target_link_options(ac PRIVATE -static)

# libbpf's static archive does not pull in its Libs.private dependencies
# (typically libzstd, sometimes additional elf/z transitive deps). The
# PkgConfig::LIBBPF imported target only carries the dynamic link line;
# LIBBPF_STATIC_LIBRARIES is populated by pkg_check_modules from Libs.private
# and gives the correct list and order for static linking.
target_link_libraries(ac PRIVATE ${LIBBPF_STATIC_LIBRARIES})

# `sudo cmake --install <build-dir>` installs the binary as
# /usr/local/bin/ac (or wherever CMAKE_INSTALL_PREFIX points) with the
# setuid bit set and owned by root (root because that's whoever runs the
# install).
install(TARGETS ac
    RUNTIME DESTINATION bin
    PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE
        WORLD_READ WORLD_EXECUTE
        SETUID
)
