# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

add_executable(enforcer-cli main.c)

target_compile_features(enforcer-cli PRIVATE c_std_11)

target_compile_options(enforcer-cli PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror
)

target_link_libraries(enforcer-cli
    PRIVATE
        ac_loader_runtime
)
