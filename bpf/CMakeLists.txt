# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

set(BPF_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}"
    ${LIBBPF_INCLUDE_DIRS}
)

add_bpf_object(hello_world hello_world.bpf.c
    VMLINUX_H "${VmlinuxH_INCLUDE_DIR}"
    INCLUDES ${BPF_INCLUDE_DIRS}
)

set(COMBINED_BPF_O "${CMAKE_CURRENT_BINARY_DIR}/combined_bpf_lib.o")
set(BPF_SKELETON_H "${CMAKE_CURRENT_BINARY_DIR}/bpf-skeleton.h")

add_bpf_skeleton(bpf_skeleton
    OBJECTS    hello_world
    COMBINED_O "${COMBINED_BPF_O}"
    SKELETON_H "${BPF_SKELETON_H}"
)

set(BPF_SKELETON_HEADER "${BPF_SKELETON_H}" PARENT_SCOPE)
