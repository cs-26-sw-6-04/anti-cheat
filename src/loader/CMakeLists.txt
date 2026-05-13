# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

cmake_path(GET BPF_SKELETON_HEADER PARENT_PATH skeleton_dir)

add_library(ac_loader_runtime STATIC
    ac.c
)

target_include_directories(ac_loader_runtime
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${PROJECT_SOURCE_DIR}/src/shared"
    PRIVATE
        "${skeleton_dir}"
)

target_compile_definitions(ac_loader_runtime
    PRIVATE
        _GNU_SOURCE  # syscall(2), pidfd-related declarations
)

target_link_libraries(ac_loader_runtime
    PUBLIC
        libbpf::libbpf
)

add_dependencies(ac_loader_runtime enforcers_skeleton)
