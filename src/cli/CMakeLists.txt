# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

add_executable(ac main.c)

target_link_libraries(ac
    PRIVATE
        ac_loader_runtime
)
