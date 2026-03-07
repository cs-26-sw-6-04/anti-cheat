# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

add_executable(ac-loader main.c)

cmake_path(GET BPF_SKELETON_HEADER PARENT_PATH skeleton_dir)
target_include_directories(ac-loader PRIVATE
    "${skeleton_dir}"
    "${PROJECT_SOURCE_DIR}/bpf"
)

target_link_libraries(ac-loader PRIVATE
    PkgConfig::LIBBPF
    elf
    z
)

add_dependencies(ac-loader bpf_skeleton)
