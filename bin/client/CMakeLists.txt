# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

add_executable(client main.c)

target_compile_features(client PRIVATE c_std_11)

target_compile_options(client PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror
)
