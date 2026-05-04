# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

add_executable(ac main.c)

target_link_libraries(ac
    PRIVATE
        ac_loader_runtime
)

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
